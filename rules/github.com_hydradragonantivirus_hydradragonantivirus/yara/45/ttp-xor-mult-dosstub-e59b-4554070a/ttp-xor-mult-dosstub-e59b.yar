rule TTP_XOR_MULT_DOSStub_e59b {
  strings:
    $key_e59b = { b1 f3 [2] c5 eb [2] 82 e9 [2] c5 f8 [2] 8b f4 [2] 87 fe [2] 90 f5 [2] 8b bb [2] b6 }

  condition:
    any of them
}