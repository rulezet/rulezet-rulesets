rule TTP_XOR_MULT_DOSStub_1007 {
  strings:
    $key_1007 = { 44 6f [2] 30 77 [2] 77 75 [2] 30 64 [2] 7e 68 [2] 72 62 [2] 65 69 [2] 7e 27 [2] 43 }

  condition:
    any of them
}