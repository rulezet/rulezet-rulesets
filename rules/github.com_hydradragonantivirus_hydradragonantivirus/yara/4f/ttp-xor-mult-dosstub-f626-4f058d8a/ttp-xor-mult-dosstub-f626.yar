rule TTP_XOR_MULT_DOSStub_f626 {
  strings:
    $key_f626 = { a2 4e [2] d6 56 [2] 91 54 [2] d6 45 [2] 98 49 [2] 94 43 [2] 83 48 [2] 98 06 [2] a5 }

  condition:
    any of them
}