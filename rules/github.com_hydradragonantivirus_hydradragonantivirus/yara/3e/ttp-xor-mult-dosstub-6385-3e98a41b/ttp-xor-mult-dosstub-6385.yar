rule TTP_XOR_MULT_DOSStub_6385 {
  strings:
    $key_6385 = { 37 ed [2] 43 f5 [2] 04 f7 [2] 43 e6 [2] 0d ea [2] 01 e0 [2] 16 eb [2] 0d a5 [2] 30 }

  condition:
    any of them
}