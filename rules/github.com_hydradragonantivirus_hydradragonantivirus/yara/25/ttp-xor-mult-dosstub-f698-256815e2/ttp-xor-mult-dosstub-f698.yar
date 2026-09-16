rule TTP_XOR_MULT_DOSStub_f698 {
  strings:
    $key_f698 = { a2 f0 [2] d6 e8 [2] 91 ea [2] d6 fb [2] 98 f7 [2] 94 fd [2] 83 f6 [2] 98 b8 [2] a5 }

  condition:
    any of them
}