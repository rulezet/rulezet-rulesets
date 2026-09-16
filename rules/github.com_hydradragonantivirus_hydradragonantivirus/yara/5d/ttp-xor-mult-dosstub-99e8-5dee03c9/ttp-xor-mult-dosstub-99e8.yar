rule TTP_XOR_MULT_DOSStub_99e8 {
  strings:
    $key_99e8 = { cd 80 [2] b9 98 [2] fe 9a [2] b9 8b [2] f7 87 [2] fb 8d [2] ec 86 [2] f7 c8 [2] ca }

  condition:
    any of them
}