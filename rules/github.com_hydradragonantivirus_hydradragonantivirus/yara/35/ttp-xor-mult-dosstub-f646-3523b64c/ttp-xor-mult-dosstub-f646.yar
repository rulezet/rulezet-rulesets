rule TTP_XOR_MULT_DOSStub_f646 {
  strings:
    $key_f646 = { a2 2e [2] d6 36 [2] 91 34 [2] d6 25 [2] 98 29 [2] 94 23 [2] 83 28 [2] 98 66 [2] a5 }

  condition:
    any of them
}