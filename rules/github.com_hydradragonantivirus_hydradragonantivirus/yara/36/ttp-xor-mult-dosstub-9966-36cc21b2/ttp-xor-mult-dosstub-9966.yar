rule TTP_XOR_MULT_DOSStub_9966 {
  strings:
    $key_9966 = { cd 0e [2] b9 16 [2] fe 14 [2] b9 05 [2] f7 09 [2] fb 03 [2] ec 08 [2] f7 46 [2] ca }

  condition:
    any of them
}