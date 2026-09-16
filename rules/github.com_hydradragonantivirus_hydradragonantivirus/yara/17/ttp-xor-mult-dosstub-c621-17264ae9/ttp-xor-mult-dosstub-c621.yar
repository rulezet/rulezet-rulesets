rule TTP_XOR_MULT_DOSStub_c621 {
  strings:
    $key_c621 = { 92 49 [2] e6 51 [2] a1 53 [2] e6 42 [2] a8 4e [2] a4 44 [2] b3 4f [2] a8 01 [2] 95 }

  condition:
    any of them
}