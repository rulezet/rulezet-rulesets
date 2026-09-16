rule TTP_XOR_MULT_DOSStub_4274 {
  strings:
    $key_4274 = { 16 1c [2] 62 04 [2] 25 06 [2] 62 17 [2] 2c 1b [2] 20 11 [2] 37 1a [2] 2c 54 [2] 11 }

  condition:
    any of them
}