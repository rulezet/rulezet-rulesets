rule TTP_XOR_MULT_DOSStub_f027 {
  strings:
    $key_f027 = { a4 4f [2] d0 57 [2] 97 55 [2] d0 44 [2] 9e 48 [2] 92 42 [2] 85 49 [2] 9e 07 [2] a3 }

  condition:
    any of them
}