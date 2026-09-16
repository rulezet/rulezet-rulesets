rule TTP_XOR_MULT_DOSStub_9977 {
  strings:
    $key_9977 = { cd 1f [2] b9 07 [2] fe 05 [2] b9 14 [2] f7 18 [2] fb 12 [2] ec 19 [2] f7 57 [2] ca }

  condition:
    any of them
}