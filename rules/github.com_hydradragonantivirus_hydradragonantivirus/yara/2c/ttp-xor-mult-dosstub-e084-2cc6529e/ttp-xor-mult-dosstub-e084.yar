rule TTP_XOR_MULT_DOSStub_e084 {
  strings:
    $key_e084 = { b4 ec [2] c0 f4 [2] 87 f6 [2] c0 e7 [2] 8e eb [2] 82 e1 [2] 95 ea [2] 8e a4 [2] b3 }

  condition:
    any of them
}