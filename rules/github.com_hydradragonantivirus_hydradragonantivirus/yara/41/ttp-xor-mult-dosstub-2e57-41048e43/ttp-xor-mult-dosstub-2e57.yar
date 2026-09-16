rule TTP_XOR_MULT_DOSStub_2e57 {
  strings:
    $key_2e57 = { 7a 3f [2] 0e 27 [2] 49 25 [2] 0e 34 [2] 40 38 [2] 4c 32 [2] 5b 39 [2] 40 77 [2] 7d }

  condition:
    any of them
}