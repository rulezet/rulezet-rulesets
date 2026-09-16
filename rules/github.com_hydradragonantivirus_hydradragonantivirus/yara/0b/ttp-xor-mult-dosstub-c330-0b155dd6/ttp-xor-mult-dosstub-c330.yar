rule TTP_XOR_MULT_DOSStub_c330 {
  strings:
    $key_c330 = { 97 58 [2] e3 40 [2] a4 42 [2] e3 53 [2] ad 5f [2] a1 55 [2] b6 5e [2] ad 10 [2] 90 }

  condition:
    any of them
}