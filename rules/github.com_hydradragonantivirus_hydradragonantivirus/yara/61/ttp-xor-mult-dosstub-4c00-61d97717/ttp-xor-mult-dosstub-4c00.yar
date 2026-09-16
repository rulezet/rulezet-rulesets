rule TTP_XOR_MULT_DOSStub_4c00 {
  strings:
    $key_4c00 = { 18 68 [2] 6c 70 [2] 2b 72 [2] 6c 63 [2] 22 6f [2] 2e 65 [2] 39 6e [2] 22 20 [2] 1f }

  condition:
    any of them
}