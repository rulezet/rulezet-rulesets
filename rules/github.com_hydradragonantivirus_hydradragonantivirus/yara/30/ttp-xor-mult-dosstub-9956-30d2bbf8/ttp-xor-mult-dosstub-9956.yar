rule TTP_XOR_MULT_DOSStub_9956 {
  strings:
    $key_9956 = { cd 3e [2] b9 26 [2] fe 24 [2] b9 35 [2] f7 39 [2] fb 33 [2] ec 38 [2] f7 76 [2] ca }

  condition:
    any of them
}