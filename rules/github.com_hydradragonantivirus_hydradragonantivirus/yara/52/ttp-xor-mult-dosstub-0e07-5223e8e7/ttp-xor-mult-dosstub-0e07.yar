rule TTP_XOR_MULT_DOSStub_0e07 {
  strings:
    $key_0e07 = { 5a 6f [2] 2e 77 [2] 69 75 [2] 2e 64 [2] 60 68 [2] 6c 62 [2] 7b 69 [2] 60 27 [2] 5d }

  condition:
    any of them
}