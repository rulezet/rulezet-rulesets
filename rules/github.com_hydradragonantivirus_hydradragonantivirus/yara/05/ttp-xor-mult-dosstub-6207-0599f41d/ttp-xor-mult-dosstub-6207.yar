rule TTP_XOR_MULT_DOSStub_6207 {
  strings:
    $key_6207 = { 36 6f [2] 42 77 [2] 05 75 [2] 42 64 [2] 0c 68 [2] 00 62 [2] 17 69 [2] 0c 27 [2] 31 }

  condition:
    any of them
}