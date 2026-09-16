rule TTP_XOR_MULT_DOSStub_9952 {
  strings:
    $key_9952 = { cd 3a [2] b9 22 [2] fe 20 [2] b9 31 [2] f7 3d [2] fb 37 [2] ec 3c [2] f7 72 [2] ca }

  condition:
    any of them
}