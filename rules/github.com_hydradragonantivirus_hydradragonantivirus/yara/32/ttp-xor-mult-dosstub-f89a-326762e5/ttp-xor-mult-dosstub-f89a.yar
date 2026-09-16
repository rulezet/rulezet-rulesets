rule TTP_XOR_MULT_DOSStub_f89a {
  strings:
    $key_f89a = { ac f2 [2] d8 ea [2] 9f e8 [2] d8 f9 [2] 96 f5 [2] 9a ff [2] 8d f4 [2] 96 ba [2] ab }

  condition:
    any of them
}