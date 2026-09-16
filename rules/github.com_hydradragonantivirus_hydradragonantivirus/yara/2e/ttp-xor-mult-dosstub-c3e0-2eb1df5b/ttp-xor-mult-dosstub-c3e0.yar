rule TTP_XOR_MULT_DOSStub_c3e0 {
  strings:
    $key_c3e0 = { 97 88 [2] e3 90 [2] a4 92 [2] e3 83 [2] ad 8f [2] a1 85 [2] b6 8e [2] ad c0 [2] 90 }

  condition:
    any of them
}