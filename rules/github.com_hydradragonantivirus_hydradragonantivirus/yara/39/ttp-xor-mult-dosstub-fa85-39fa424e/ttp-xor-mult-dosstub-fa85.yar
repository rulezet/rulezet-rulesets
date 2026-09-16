rule TTP_XOR_MULT_DOSStub_fa85 {
  strings:
    $key_fa85 = { ae ed [2] da f5 [2] 9d f7 [2] da e6 [2] 94 ea [2] 98 e0 [2] 8f eb [2] 94 a5 [2] a9 }

  condition:
    any of them
}