rule TTP_XOR_MULT_DOSStub_7e66 {
  strings:
    $key_7e66 = { 2a 0e [2] 5e 16 [2] 19 14 [2] 5e 05 [2] 10 09 [2] 1c 03 [2] 0b 08 [2] 10 46 [2] 2d }

  condition:
    any of them
}