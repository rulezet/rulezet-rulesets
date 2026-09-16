rule TTP_XOR_MULT_DOSStub_f6d2 {
  strings:
    $key_f6d2 = { a2 ba [2] d6 a2 [2] 91 a0 [2] d6 b1 [2] 98 bd [2] 94 b7 [2] 83 bc [2] 98 f2 [2] a5 }

  condition:
    any of them
}