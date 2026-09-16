rule TTP_XOR_MULT_DOSStub_3727 {
  strings:
    $key_3727 = { 63 4f [2] 17 57 [2] 50 55 [2] 17 44 [2] 59 48 [2] 55 42 [2] 42 49 [2] 59 07 [2] 64 }

  condition:
    any of them
}