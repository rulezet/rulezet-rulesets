rule TTP_XOR_MULT_DOSStub_f6d0 {
  strings:
    $key_f6d0 = { a2 b8 [2] d6 a0 [2] 91 a2 [2] d6 b3 [2] 98 bf [2] 94 b5 [2] 83 be [2] 98 f0 [2] a5 }

  condition:
    any of them
}