rule TTP_XOR_MULT_DOSStub_f885 {
  strings:
    $key_f885 = { ac ed [2] d8 f5 [2] 9f f7 [2] d8 e6 [2] 96 ea [2] 9a e0 [2] 8d eb [2] 96 a5 [2] ab }

  condition:
    any of them
}