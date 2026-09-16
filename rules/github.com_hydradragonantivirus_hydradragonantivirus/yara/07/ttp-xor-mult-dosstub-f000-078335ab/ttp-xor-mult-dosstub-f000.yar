rule TTP_XOR_MULT_DOSStub_f000 {
  strings:
    $key_f000 = { a4 68 [2] d0 70 [2] 97 72 [2] d0 63 [2] 9e 6f [2] 92 65 [2] 85 6e [2] 9e 20 [2] a3 }

  condition:
    any of them
}