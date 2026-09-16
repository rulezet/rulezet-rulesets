rule TTP_XOR_MULT_DOSStub_f051 {
  strings:
    $key_f051 = { a4 39 [2] d0 21 [2] 97 23 [2] d0 32 [2] 9e 3e [2] 92 34 [2] 85 3f [2] 9e 71 [2] a3 }

  condition:
    any of them
}