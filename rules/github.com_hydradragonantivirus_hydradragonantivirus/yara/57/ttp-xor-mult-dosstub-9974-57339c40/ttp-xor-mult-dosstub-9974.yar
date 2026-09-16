rule TTP_XOR_MULT_DOSStub_9974 {
  strings:
    $key_9974 = { cd 1c [2] b9 04 [2] fe 06 [2] b9 17 [2] f7 1b [2] fb 11 [2] ec 1a [2] f7 54 [2] ca }

  condition:
    any of them
}