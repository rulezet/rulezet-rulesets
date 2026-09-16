rule TTP_XOR_MULT_DOSStub_5007 {
  strings:
    $key_5007 = { 04 6f [2] 70 77 [2] 37 75 [2] 70 64 [2] 3e 68 [2] 32 62 [2] 25 69 [2] 3e 27 [2] 03 }

  condition:
    any of them
}