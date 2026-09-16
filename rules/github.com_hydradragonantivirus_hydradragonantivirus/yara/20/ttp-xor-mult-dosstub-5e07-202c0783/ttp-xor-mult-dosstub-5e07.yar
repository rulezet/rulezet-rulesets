rule TTP_XOR_MULT_DOSStub_5e07 {
  strings:
    $key_5e07 = { 0a 6f [2] 7e 77 [2] 39 75 [2] 7e 64 [2] 30 68 [2] 3c 62 [2] 2b 69 [2] 30 27 [2] 0d }

  condition:
    any of them
}