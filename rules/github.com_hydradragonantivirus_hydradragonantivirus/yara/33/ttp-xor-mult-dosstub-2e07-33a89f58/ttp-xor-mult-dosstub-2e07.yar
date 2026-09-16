rule TTP_XOR_MULT_DOSStub_2e07 {
  strings:
    $key_2e07 = { 7a 6f [2] 0e 77 [2] 49 75 [2] 0e 64 [2] 40 68 [2] 4c 62 [2] 5b 69 [2] 40 27 [2] 7d }

  condition:
    any of them
}