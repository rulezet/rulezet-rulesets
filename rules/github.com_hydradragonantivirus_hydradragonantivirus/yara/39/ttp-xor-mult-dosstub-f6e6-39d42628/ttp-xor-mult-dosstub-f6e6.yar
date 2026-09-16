rule TTP_XOR_MULT_DOSStub_f6e6 {
  strings:
    $key_f6e6 = { a2 8e [2] d6 96 [2] 91 94 [2] d6 85 [2] 98 89 [2] 94 83 [2] 83 88 [2] 98 c6 [2] a5 }

  condition:
    any of them
}