rule TTP_XOR_MULT_DOSStub_79ef {
  strings:
    $key_79ef = { 2d 87 [2] 59 9f [2] 1e 9d [2] 59 8c [2] 17 80 [2] 1b 8a [2] 0c 81 [2] 17 cf [2] 2a }

  condition:
    any of them
}