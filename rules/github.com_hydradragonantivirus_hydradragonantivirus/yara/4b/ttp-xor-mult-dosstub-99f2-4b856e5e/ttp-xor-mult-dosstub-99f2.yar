rule TTP_XOR_MULT_DOSStub_99f2 {
  strings:
    $key_99f2 = { cd 9a [2] b9 82 [2] fe 80 [2] b9 91 [2] f7 9d [2] fb 97 [2] ec 9c [2] f7 d2 [2] ca }

  condition:
    any of them
}