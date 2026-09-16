rule TTP_XOR_MULT_DOSStub_2e27 {
  strings:
    $key_2e27 = { 7a 4f [2] 0e 57 [2] 49 55 [2] 0e 44 [2] 40 48 [2] 4c 42 [2] 5b 49 [2] 40 07 [2] 7d }

  condition:
    any of them
}