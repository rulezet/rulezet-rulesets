rule TTP_XOR_MULT_DOSStub_c326 {
  strings:
    $key_c326 = { 97 4e [2] e3 56 [2] a4 54 [2] e3 45 [2] ad 49 [2] a1 43 [2] b6 48 [2] ad 06 [2] 90 }

  condition:
    any of them
}