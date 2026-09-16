rule TTP_XOR_MULT_DOSStub_e888 {
  strings:
    $key_e888 = { bc e0 [2] c8 f8 [2] 8f fa [2] c8 eb [2] 86 e7 [2] 8a ed [2] 9d e6 [2] 86 a8 [2] bb }

  condition:
    any of them
}