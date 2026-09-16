rule TTP_XOR_MULT_DOSStub_0407 {
  strings:
    $key_0407 = { 50 6f [2] 24 77 [2] 63 75 [2] 24 64 [2] 6a 68 [2] 66 62 [2] 71 69 [2] 6a 27 [2] 57 }

  condition:
    any of them
}