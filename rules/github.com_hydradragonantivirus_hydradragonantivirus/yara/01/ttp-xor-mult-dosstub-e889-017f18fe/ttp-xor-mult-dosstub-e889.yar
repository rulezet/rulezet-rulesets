rule TTP_XOR_MULT_DOSStub_e889 {
  strings:
    $key_e889 = { bc e1 [2] c8 f9 [2] 8f fb [2] c8 ea [2] 86 e6 [2] 8a ec [2] 9d e7 [2] 86 a9 [2] bb }

  condition:
    any of them
}