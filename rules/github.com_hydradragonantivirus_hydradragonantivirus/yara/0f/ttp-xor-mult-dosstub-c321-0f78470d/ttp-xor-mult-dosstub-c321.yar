rule TTP_XOR_MULT_DOSStub_c321 {
  strings:
    $key_c321 = { 97 49 [2] e3 51 [2] a4 53 [2] e3 42 [2] ad 4e [2] a1 44 [2] b6 4f [2] ad 01 [2] 90 }

  condition:
    any of them
}