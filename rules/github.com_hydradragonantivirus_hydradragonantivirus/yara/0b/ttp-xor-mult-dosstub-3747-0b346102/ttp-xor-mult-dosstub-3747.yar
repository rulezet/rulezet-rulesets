rule TTP_XOR_MULT_DOSStub_3747 {
  strings:
    $key_3747 = { 63 2f [2] 17 37 [2] 50 35 [2] 17 24 [2] 59 28 [2] 55 22 [2] 42 29 [2] 59 67 [2] 64 }

  condition:
    any of them
}