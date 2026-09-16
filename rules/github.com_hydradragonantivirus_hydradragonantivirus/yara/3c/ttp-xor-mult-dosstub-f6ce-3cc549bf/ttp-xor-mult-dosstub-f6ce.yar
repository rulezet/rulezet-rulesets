rule TTP_XOR_MULT_DOSStub_f6ce {
  strings:
    $key_f6ce = { a2 a6 [2] d6 be [2] 91 bc [2] d6 ad [2] 98 a1 [2] 94 ab [2] 83 a0 [2] 98 ee [2] a5 }

  condition:
    any of them
}