rule TTP_XOR_MULT_DOSStub_4c70 {
  strings:
    $key_4c70 = { 18 18 [2] 6c 00 [2] 2b 02 [2] 6c 13 [2] 22 1f [2] 2e 15 [2] 39 1e [2] 22 50 [2] 1f }

  condition:
    any of them
}