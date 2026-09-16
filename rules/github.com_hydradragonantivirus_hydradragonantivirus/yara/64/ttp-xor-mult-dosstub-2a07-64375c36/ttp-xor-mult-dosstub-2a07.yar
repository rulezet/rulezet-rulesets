rule TTP_XOR_MULT_DOSStub_2a07 {
  strings:
    $key_2a07 = { 7e 6f [2] 0a 77 [2] 4d 75 [2] 0a 64 [2] 44 68 [2] 48 62 [2] 5f 69 [2] 44 27 [2] 79 }

  condition:
    any of them
}