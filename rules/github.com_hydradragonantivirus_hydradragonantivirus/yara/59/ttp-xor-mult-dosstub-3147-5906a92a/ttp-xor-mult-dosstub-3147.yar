rule TTP_XOR_MULT_DOSStub_3147 {
  strings:
    $key_3147 = { 65 2f [2] 11 37 [2] 56 35 [2] 11 24 [2] 5f 28 [2] 53 22 [2] 44 29 [2] 5f 67 [2] 62 }

  condition:
    any of them
}