rule TTP_XOR_MULT_DOSStub_99f4 {
  strings:
    $key_99f4 = { cd 9c [2] b9 84 [2] fe 86 [2] b9 97 [2] f7 9b [2] fb 91 [2] ec 9a [2] f7 d4 [2] ca }

  condition:
    any of them
}