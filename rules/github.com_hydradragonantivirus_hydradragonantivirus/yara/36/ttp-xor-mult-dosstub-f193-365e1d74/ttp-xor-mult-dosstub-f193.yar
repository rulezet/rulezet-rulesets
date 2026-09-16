rule TTP_XOR_MULT_DOSStub_f193 {
  strings:
    $key_f193 = { a5 fb [2] d1 e3 [2] 96 e1 [2] d1 f0 [2] 9f fc [2] 93 f6 [2] 84 fd [2] 9f b3 [2] a2 }

  condition:
    any of them
}