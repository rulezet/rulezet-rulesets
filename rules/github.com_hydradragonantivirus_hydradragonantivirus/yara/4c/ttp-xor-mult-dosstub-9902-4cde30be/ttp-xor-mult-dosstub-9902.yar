rule TTP_XOR_MULT_DOSStub_9902 {
  strings:
    $key_9902 = { cd 6a [2] b9 72 [2] fe 70 [2] b9 61 [2] f7 6d [2] fb 67 [2] ec 6c [2] f7 22 [2] ca }

  condition:
    any of them
}