rule TTP_XOR_MULT_DOSStub_3100 {
  strings:
    $key_3100 = { 65 68 [2] 11 70 [2] 56 72 [2] 11 63 [2] 5f 6f [2] 53 65 [2] 44 6e [2] 5f 20 [2] 62 }

  condition:
    any of them
}