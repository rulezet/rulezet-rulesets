rule TTP_XOR_MULT_DOSStub_9951 {
  strings:
    $key_9951 = { cd 39 [2] b9 21 [2] fe 23 [2] b9 32 [2] f7 3e [2] fb 34 [2] ec 3f [2] f7 71 [2] ca }

  condition:
    any of them
}