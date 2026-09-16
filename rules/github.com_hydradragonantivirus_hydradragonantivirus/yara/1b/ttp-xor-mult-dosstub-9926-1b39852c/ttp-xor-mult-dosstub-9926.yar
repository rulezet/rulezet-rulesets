rule TTP_XOR_MULT_DOSStub_9926 {
  strings:
    $key_9926 = { cd 4e [2] b9 56 [2] fe 54 [2] b9 45 [2] f7 49 [2] fb 43 [2] ec 48 [2] f7 06 [2] ca }

  condition:
    any of them
}