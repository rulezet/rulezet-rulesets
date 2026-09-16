rule TTP_XOR_MULT_DOSStub_4c21 {
  strings:
    $key_4c21 = { 18 49 [2] 6c 51 [2] 2b 53 [2] 6c 42 [2] 22 4e [2] 2e 44 [2] 39 4f [2] 22 01 [2] 1f }

  condition:
    any of them
}