rule TTP_XOR_MULT_DOSStub_5967 {
  strings:
    $key_5967 = { 0d 0f [2] 79 17 [2] 3e 15 [2] 79 04 [2] 37 08 [2] 3b 02 [2] 2c 09 [2] 37 47 [2] 0a }

  condition:
    any of them
}