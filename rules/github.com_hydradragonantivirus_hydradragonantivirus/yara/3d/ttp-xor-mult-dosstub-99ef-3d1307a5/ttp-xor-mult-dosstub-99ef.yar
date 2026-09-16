rule TTP_XOR_MULT_DOSStub_99ef {
  strings:
    $key_99ef = { cd 87 [2] b9 9f [2] fe 9d [2] b9 8c [2] f7 80 [2] fb 8a [2] ec 81 [2] f7 cf [2] ca }

  condition:
    any of them
}