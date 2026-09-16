rule TTP_XOR_MULT_DOSStub_c337 {
  strings:
    $key_c337 = { 97 5f [2] e3 47 [2] a4 45 [2] e3 54 [2] ad 58 [2] a1 52 [2] b6 59 [2] ad 17 [2] 90 }

  condition:
    any of them
}