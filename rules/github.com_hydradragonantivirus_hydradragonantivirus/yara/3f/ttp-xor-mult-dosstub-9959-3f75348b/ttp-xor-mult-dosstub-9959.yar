rule TTP_XOR_MULT_DOSStub_9959 {
  strings:
    $key_9959 = { cd 31 [2] b9 29 [2] fe 2b [2] b9 3a [2] f7 36 [2] fb 3c [2] ec 37 [2] f7 79 [2] ca }

  condition:
    any of them
}