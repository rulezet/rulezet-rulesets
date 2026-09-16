rule TTP_XOR_MULT_DOSStub_49ef {
  strings:
    $key_49ef = { 1d 87 [2] 69 9f [2] 2e 9d [2] 69 8c [2] 27 80 [2] 2b 8a [2] 3c 81 [2] 27 cf [2] 1a }

  condition:
    any of them
}