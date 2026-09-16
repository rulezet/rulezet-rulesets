rule TTP_XOR_MULT_DOSStub_f227 {
  strings:
    $key_f227 = { a6 4f [2] d2 57 [2] 95 55 [2] d2 44 [2] 9c 48 [2] 90 42 [2] 87 49 [2] 9c 07 [2] a1 }

  condition:
    any of them
}