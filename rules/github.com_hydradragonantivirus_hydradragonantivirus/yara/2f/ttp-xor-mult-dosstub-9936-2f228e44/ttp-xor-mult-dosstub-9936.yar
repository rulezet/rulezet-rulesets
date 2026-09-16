rule TTP_XOR_MULT_DOSStub_9936 {
  strings:
    $key_9936 = { cd 5e [2] b9 46 [2] fe 44 [2] b9 55 [2] f7 59 [2] fb 53 [2] ec 58 [2] f7 16 [2] ca }

  condition:
    any of them
}