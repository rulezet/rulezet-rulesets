rule TTP_XOR_MULT_DOSStub_3c70 {
  strings:
    $key_3c70 = { 68 18 [2] 1c 00 [2] 5b 02 [2] 1c 13 [2] 52 1f [2] 5e 15 [2] 49 1e [2] 52 50 [2] 6f }

  condition:
    any of them
}