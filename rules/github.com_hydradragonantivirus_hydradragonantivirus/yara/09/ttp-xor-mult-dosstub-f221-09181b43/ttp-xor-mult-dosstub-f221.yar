rule TTP_XOR_MULT_DOSStub_f221 {
  strings:
    $key_f221 = { a6 49 [2] d2 51 [2] 95 53 [2] d2 42 [2] 9c 4e [2] 90 44 [2] 87 4f [2] 9c 01 [2] a1 }

  condition:
    any of them
}