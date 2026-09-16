rule TTP_XOR_MULT_DOSStub_9975 {
  strings:
    $key_9975 = { cd 1d [2] b9 05 [2] fe 07 [2] b9 16 [2] f7 1a [2] fb 10 [2] ec 1b [2] f7 55 [2] ca }

  condition:
    any of them
}