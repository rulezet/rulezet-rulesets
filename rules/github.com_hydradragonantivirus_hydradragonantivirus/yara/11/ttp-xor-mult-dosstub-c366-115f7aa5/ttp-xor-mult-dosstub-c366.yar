rule TTP_XOR_MULT_DOSStub_c366 {
  strings:
    $key_c366 = { 97 0e [2] e3 16 [2] a4 14 [2] e3 05 [2] ad 09 [2] a1 03 [2] b6 08 [2] ad 46 [2] 90 }

  condition:
    any of them
}