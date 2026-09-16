rule TTP_XOR_MULT_DOSStub_9940 {
  strings:
    $key_9940 = { cd 28 [2] b9 30 [2] fe 32 [2] b9 23 [2] f7 2f [2] fb 25 [2] ec 2e [2] f7 60 [2] ca }

  condition:
    any of them
}