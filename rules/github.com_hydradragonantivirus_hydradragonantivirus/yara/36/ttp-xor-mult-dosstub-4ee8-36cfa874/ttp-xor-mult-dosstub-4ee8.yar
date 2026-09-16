rule TTP_XOR_MULT_DOSStub_4ee8 {
  strings:
    $key_4ee8 = { 1a 80 [2] 6e 98 [2] 29 9a [2] 6e 8b [2] 20 87 [2] 2c 8d [2] 3b 86 [2] 20 c8 [2] 1d }

  condition:
    any of them
}