rule TTP_XOR_MULT_DOSStub_9955 {
  strings:
    $key_9955 = { cd 3d [2] b9 25 [2] fe 27 [2] b9 36 [2] f7 3a [2] fb 30 [2] ec 3b [2] f7 75 [2] ca }

  condition:
    any of them
}