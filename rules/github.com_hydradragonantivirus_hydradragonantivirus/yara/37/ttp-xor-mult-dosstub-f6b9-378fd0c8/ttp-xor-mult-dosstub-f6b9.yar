rule TTP_XOR_MULT_DOSStub_f6b9 {
  strings:
    $key_f6b9 = { a2 d1 [2] d6 c9 [2] 91 cb [2] d6 da [2] 98 d6 [2] 94 dc [2] 83 d7 [2] 98 99 [2] a5 }

  condition:
    any of them
}