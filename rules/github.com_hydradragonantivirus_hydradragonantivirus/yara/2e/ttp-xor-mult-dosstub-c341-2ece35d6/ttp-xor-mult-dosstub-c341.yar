rule TTP_XOR_MULT_DOSStub_c341 {
  strings:
    $key_c341 = { 97 29 [2] e3 31 [2] a4 33 [2] e3 22 [2] ad 2e [2] a1 24 [2] b6 2f [2] ad 61 [2] 90 }

  condition:
    any of them
}