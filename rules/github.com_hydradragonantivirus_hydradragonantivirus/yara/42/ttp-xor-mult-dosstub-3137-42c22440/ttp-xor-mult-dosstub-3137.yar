rule TTP_XOR_MULT_DOSStub_3137 {
  strings:
    $key_3137 = { 65 5f [2] 11 47 [2] 56 45 [2] 11 54 [2] 5f 58 [2] 53 52 [2] 44 59 [2] 5f 17 [2] 62 }

  condition:
    any of them
}