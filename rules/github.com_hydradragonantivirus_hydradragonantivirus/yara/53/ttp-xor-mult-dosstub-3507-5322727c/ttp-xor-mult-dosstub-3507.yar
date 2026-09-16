rule TTP_XOR_MULT_DOSStub_3507 {
  strings:
    $key_3507 = { 61 6f [2] 15 77 [2] 52 75 [2] 15 64 [2] 5b 68 [2] 57 62 [2] 40 69 [2] 5b 27 [2] 66 }

  condition:
    any of them
}