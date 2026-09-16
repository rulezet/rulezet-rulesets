rule TTP_XOR_MULT_DOSStub_7c27 {
  strings:
    $key_7c27 = { 28 4f [2] 5c 57 [2] 1b 55 [2] 5c 44 [2] 12 48 [2] 1e 42 [2] 09 49 [2] 12 07 [2] 2f }

  condition:
    any of them
}