rule TTP_XOR_MULT_DOSStub_7c07 {
  strings:
    $key_7c07 = { 28 6f [2] 5c 77 [2] 1b 75 [2] 5c 64 [2] 12 68 [2] 1e 62 [2] 09 69 [2] 12 27 [2] 2f }

  condition:
    any of them
}