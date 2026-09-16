rule TTP_XOR_MULT_DOSStub_c427 {
  strings:
    $key_c427 = { 90 4f [2] e4 57 [2] a3 55 [2] e4 44 [2] aa 48 [2] a6 42 [2] b1 49 [2] aa 07 [2] 97 }

  condition:
    any of them
}