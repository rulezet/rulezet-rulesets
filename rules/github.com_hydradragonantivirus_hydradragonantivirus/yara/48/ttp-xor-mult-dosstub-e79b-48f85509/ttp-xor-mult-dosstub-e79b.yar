rule TTP_XOR_MULT_DOSStub_e79b {
  strings:
    $key_e79b = { b3 f3 [2] c7 eb [2] 80 e9 [2] c7 f8 [2] 89 f4 [2] 85 fe [2] 92 f5 [2] 89 bb [2] b4 }

  condition:
    any of them
}