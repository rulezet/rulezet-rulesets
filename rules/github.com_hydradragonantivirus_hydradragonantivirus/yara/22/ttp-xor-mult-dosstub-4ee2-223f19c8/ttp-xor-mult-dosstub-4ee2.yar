rule TTP_XOR_MULT_DOSStub_4ee2 {
  strings:
    $key_4ee2 = { 1a 8a [2] 6e 92 [2] 29 90 [2] 6e 81 [2] 20 8d [2] 2c 87 [2] 3b 8c [2] 20 c2 [2] 1d }

  condition:
    any of them
}