rule TTP_XOR_MULT_DOSStub_7707 {
  strings:
    $key_7707 = { 23 6f [2] 57 77 [2] 10 75 [2] 57 64 [2] 19 68 [2] 15 62 [2] 02 69 [2] 19 27 [2] 24 }

  condition:
    any of them
}