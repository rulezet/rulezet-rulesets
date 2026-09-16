rule TTP_XOR_MULT_DOSStub_9931 {
  strings:
    $key_9931 = { cd 59 [2] b9 41 [2] fe 43 [2] b9 52 [2] f7 5e [2] fb 54 [2] ec 5f [2] f7 11 [2] ca }

  condition:
    any of them
}