rule TTP_XOR_MULT_DOSStub_fe8f {
  strings:
    $key_fe8f = { aa e7 [2] de ff [2] 99 fd [2] de ec [2] 90 e0 [2] 9c ea [2] 8b e1 [2] 90 af [2] ad }

  condition:
    any of them
}