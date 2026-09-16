rule TTP_XOR_MULT_DOSStub_e890 {
  strings:
    $key_e890 = { bc f8 [2] c8 e0 [2] 8f e2 [2] c8 f3 [2] 86 ff [2] 8a f5 [2] 9d fe [2] 86 b0 [2] bb }

  condition:
    any of them
}