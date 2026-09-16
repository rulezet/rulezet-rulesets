rule TTP_XOR_MULT_DOSStub_f640 {
  strings:
    $key_f640 = { a2 28 [2] d6 30 [2] 91 32 [2] d6 23 [2] 98 2f [2] 94 25 [2] 83 2e [2] 98 60 [2] a5 }

  condition:
    any of them
}