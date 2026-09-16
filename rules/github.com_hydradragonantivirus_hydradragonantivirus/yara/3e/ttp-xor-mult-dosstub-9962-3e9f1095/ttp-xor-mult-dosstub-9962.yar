rule TTP_XOR_MULT_DOSStub_9962 {
  strings:
    $key_9962 = { cd 0a [2] b9 12 [2] fe 10 [2] b9 01 [2] f7 0d [2] fb 07 [2] ec 0c [2] f7 42 [2] ca }

  condition:
    any of them
}