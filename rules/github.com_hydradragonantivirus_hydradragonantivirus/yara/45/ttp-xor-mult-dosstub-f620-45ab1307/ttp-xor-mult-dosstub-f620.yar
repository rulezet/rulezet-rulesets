rule TTP_XOR_MULT_DOSStub_f620 {
  strings:
    $key_f620 = { a2 48 [2] d6 50 [2] 91 52 [2] d6 43 [2] 98 4f [2] 94 45 [2] 83 4e [2] 98 00 [2] a5 }

  condition:
    any of them
}