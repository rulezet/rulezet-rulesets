rule TTP_XOR_MULT_DOSStub_f6e2 {
  strings:
    $key_f6e2 = { a2 8a [2] d6 92 [2] 91 90 [2] d6 81 [2] 98 8d [2] 94 87 [2] 83 8c [2] 98 c2 [2] a5 }

  condition:
    any of them
}