rule TTP_XOR_MULT_DOSStub_3707 {
  strings:
    $key_3707 = { 63 6f [2] 17 77 [2] 50 75 [2] 17 64 [2] 59 68 [2] 55 62 [2] 42 69 [2] 59 27 [2] 64 }

  condition:
    any of them
}