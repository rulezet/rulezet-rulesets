rule TTP_XOR_MULT_DOSStub_4c27 {
  strings:
    $key_4c27 = { 18 4f [2] 6c 57 [2] 2b 55 [2] 6c 44 [2] 22 48 [2] 2e 42 [2] 39 49 [2] 22 07 [2] 1f }

  condition:
    any of them
}