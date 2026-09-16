rule TTP_XOR_MULT_DOSStub_f050 {
  strings:
    $key_f050 = { a4 38 [2] d0 20 [2] 97 22 [2] d0 33 [2] 9e 3f [2] 92 35 [2] 85 3e [2] 9e 70 [2] a3 }

  condition:
    any of them
}