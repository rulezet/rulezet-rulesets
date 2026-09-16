rule TTP_XOR_MULT_DOSStub_4eef {
  strings:
    $key_4eef = { 1a 87 [2] 6e 9f [2] 29 9d [2] 6e 8c [2] 20 80 [2] 2c 8a [2] 3b 81 [2] 20 cf [2] 1d }

  condition:
    any of them
}