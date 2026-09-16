rule TTP_XOR_MULT_DOSStub_f026 {
  strings:
    $key_f026 = { a4 4e [2] d0 56 [2] 97 54 [2] d0 45 [2] 9e 49 [2] 92 43 [2] 85 48 [2] 9e 06 [2] a3 }

  condition:
    any of them
}