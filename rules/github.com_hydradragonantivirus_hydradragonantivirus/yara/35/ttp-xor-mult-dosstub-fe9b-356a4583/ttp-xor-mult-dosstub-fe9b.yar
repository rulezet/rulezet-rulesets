rule TTP_XOR_MULT_DOSStub_fe9b {
  strings:
    $key_fe9b = { aa f3 [2] de eb [2] 99 e9 [2] de f8 [2] 90 f4 [2] 9c fe [2] 8b f5 [2] 90 bb [2] ad }

  condition:
    any of them
}