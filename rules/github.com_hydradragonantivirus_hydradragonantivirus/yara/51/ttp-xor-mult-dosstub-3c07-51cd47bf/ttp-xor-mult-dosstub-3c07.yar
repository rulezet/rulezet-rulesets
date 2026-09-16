rule TTP_XOR_MULT_DOSStub_3c07 {
  strings:
    $key_3c07 = { 68 6f [2] 1c 77 [2] 5b 75 [2] 1c 64 [2] 52 68 [2] 5e 62 [2] 49 69 [2] 52 27 [2] 6f }

  condition:
    any of them
}