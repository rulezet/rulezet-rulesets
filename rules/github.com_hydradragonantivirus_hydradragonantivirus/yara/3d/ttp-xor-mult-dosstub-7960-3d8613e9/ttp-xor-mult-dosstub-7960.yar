rule TTP_XOR_MULT_DOSStub_7960 {
  strings:
    $key_7960 = { 2d 08 [2] 59 10 [2] 1e 12 [2] 59 03 [2] 17 0f [2] 1b 05 [2] 0c 0e [2] 17 40 [2] 2a }

  condition:
    any of them
}