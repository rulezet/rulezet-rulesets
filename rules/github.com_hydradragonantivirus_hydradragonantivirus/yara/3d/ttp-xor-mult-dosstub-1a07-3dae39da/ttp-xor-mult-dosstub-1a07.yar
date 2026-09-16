rule TTP_XOR_MULT_DOSStub_1a07 {
  strings:
    $key_1a07 = { 4e 6f [2] 3a 77 [2] 7d 75 [2] 3a 64 [2] 74 68 [2] 78 62 [2] 6f 69 [2] 74 27 [2] 49 }

  condition:
    any of them
}