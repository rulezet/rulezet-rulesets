rule TTP_XOR_MULT_DOSStub_c247 {
  strings:
    $key_c247 = { 96 2f [2] e2 37 [2] a5 35 [2] e2 24 [2] ac 28 [2] a0 22 [2] b7 29 [2] ac 67 [2] 91 }

  condition:
    any of them
}