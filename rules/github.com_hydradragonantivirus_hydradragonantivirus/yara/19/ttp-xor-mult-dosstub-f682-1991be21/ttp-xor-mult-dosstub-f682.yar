rule TTP_XOR_MULT_DOSStub_f682 {
  strings:
    $key_f682 = { a2 ea [2] d6 f2 [2] 91 f0 [2] d6 e1 [2] 98 ed [2] 94 e7 [2] 83 ec [2] 98 a2 [2] a5 }

  condition:
    any of them
}