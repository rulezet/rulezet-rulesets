rule TTP_XOR_MULT_DOSStub_f627 {
  strings:
    $key_f627 = { a2 4f [2] d6 57 [2] 91 55 [2] d6 44 [2] 98 48 [2] 94 42 [2] 83 49 [2] 98 07 [2] a5 }

  condition:
    any of them
}