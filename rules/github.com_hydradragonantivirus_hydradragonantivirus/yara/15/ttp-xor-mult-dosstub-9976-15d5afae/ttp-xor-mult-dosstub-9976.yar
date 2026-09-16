rule TTP_XOR_MULT_DOSStub_9976 {
  strings:
    $key_9976 = { cd 1e [2] b9 06 [2] fe 04 [2] b9 15 [2] f7 19 [2] fb 13 [2] ec 18 [2] f7 56 [2] ca }

  condition:
    any of them
}