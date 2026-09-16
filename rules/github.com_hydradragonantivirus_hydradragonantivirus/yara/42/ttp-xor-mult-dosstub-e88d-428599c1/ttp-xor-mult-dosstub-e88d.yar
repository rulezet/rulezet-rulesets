rule TTP_XOR_MULT_DOSStub_e88d {
  strings:
    $key_e88d = { bc e5 [2] c8 fd [2] 8f ff [2] c8 ee [2] 86 e2 [2] 8a e8 [2] 9d e3 [2] 86 ad [2] bb }

  condition:
    any of them
}