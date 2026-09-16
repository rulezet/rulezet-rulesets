rule TTP_XOR_MULT_DOSStub_f696 {
  strings:
    $key_f696 = { a2 fe [2] d6 e6 [2] 91 e4 [2] d6 f5 [2] 98 f9 [2] 94 f3 [2] 83 f8 [2] 98 b6 [2] a5 }

  condition:
    any of them
}