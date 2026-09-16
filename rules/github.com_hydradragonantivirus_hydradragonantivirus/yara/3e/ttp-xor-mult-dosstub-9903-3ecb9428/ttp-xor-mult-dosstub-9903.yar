rule TTP_XOR_MULT_DOSStub_9903 {
  strings:
    $key_9903 = { cd 6b [2] b9 73 [2] fe 71 [2] b9 60 [2] f7 6c [2] fb 66 [2] ec 6d [2] f7 23 [2] ca }

  condition:
    any of them
}