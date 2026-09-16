rule TTP_XOR_MULT_DOSStub_9964 {
  strings:
    $key_9964 = { cd 0c [2] b9 14 [2] fe 16 [2] b9 07 [2] f7 0b [2] fb 01 [2] ec 0a [2] f7 44 [2] ca }

  condition:
    any of them
}