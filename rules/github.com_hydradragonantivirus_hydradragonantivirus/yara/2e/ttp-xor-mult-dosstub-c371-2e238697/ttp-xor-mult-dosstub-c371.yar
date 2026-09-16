rule TTP_XOR_MULT_DOSStub_c371 {
  strings:
    $key_c371 = { 97 19 [2] e3 01 [2] a4 03 [2] e3 12 [2] ad 1e [2] a1 14 [2] b6 1f [2] ad 51 [2] 90 }

  condition:
    any of them
}