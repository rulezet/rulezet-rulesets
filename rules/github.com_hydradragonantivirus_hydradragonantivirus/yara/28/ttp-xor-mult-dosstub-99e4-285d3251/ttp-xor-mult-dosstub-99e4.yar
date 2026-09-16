rule TTP_XOR_MULT_DOSStub_99e4 {
  strings:
    $key_99e4 = { cd 8c [2] b9 94 [2] fe 96 [2] b9 87 [2] f7 8b [2] fb 81 [2] ec 8a [2] f7 c4 [2] ca }

  condition:
    any of them
}