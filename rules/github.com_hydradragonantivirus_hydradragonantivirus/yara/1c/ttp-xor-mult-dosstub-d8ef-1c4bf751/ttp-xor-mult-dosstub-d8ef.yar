rule TTP_XOR_MULT_DOSStub_d8ef {
  strings:
    $key_d8ef = { 8c 87 [2] f8 9f [2] bf 9d [2] f8 8c [2] b6 80 [2] ba 8a [2] ad 81 [2] b6 cf [2] 8b }

  condition:
    any of them
}