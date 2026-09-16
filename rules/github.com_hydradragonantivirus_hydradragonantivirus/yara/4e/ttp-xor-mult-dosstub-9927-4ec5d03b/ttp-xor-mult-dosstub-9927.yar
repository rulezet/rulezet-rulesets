rule TTP_XOR_MULT_DOSStub_9927 {
  strings:
    $key_9927 = { cd 4f [2] b9 57 [2] fe 55 [2] b9 44 [2] f7 48 [2] fb 42 [2] ec 49 [2] f7 07 [2] ca }

  condition:
    any of them
}