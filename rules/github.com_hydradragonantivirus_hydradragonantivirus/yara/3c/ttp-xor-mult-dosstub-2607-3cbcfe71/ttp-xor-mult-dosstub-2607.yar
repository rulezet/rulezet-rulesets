rule TTP_XOR_MULT_DOSStub_2607 {
  strings:
    $key_2607 = { 72 6f [2] 06 77 [2] 41 75 [2] 06 64 [2] 48 68 [2] 44 62 [2] 53 69 [2] 48 27 [2] 75 }

  condition:
    any of them
}