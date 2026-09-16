rule TTP_XOR_MULT_DOSStub_3207 {
  strings:
    $key_3207 = { 66 6f [2] 12 77 [2] 55 75 [2] 12 64 [2] 5c 68 [2] 50 62 [2] 47 69 [2] 5c 27 [2] 61 }

  condition:
    any of them
}