rule TTP_XOR_MULT_DOSStub_7c11 {
  strings:
    $key_7c11 = { 28 79 [2] 5c 61 [2] 1b 63 [2] 5c 72 [2] 12 7e [2] 1e 74 [2] 09 7f [2] 12 31 [2] 2f }

  condition:
    any of them
}