rule TTP_XOR_MULT_DOSStub_9917 {
  strings:
    $key_9917 = { cd 7f [2] b9 67 [2] fe 65 [2] b9 74 [2] f7 78 [2] fb 72 [2] ec 79 [2] f7 37 [2] ca }

  condition:
    any of them
}