rule TTP_XOR_MULT_DOSStub_3e07 {
  strings:
    $key_3e07 = { 6a 6f [2] 1e 77 [2] 59 75 [2] 1e 64 [2] 50 68 [2] 5c 62 [2] 4b 69 [2] 50 27 [2] 6d }

  condition:
    any of them
}