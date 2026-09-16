rule TTP_XOR_MULT_DOSStub_f6f7 {
  strings:
    $key_f6f7 = { a2 9f [2] d6 87 [2] 91 85 [2] d6 94 [2] 98 98 [2] 94 92 [2] 83 99 [2] 98 d7 [2] a5 }

  condition:
    any of them
}