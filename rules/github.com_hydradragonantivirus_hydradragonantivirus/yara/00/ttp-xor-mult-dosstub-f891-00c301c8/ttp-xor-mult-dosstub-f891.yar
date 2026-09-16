rule TTP_XOR_MULT_DOSStub_f891 {
  strings:
    $key_f891 = { ac f9 [2] d8 e1 [2] 9f e3 [2] d8 f2 [2] 96 fe [2] 9a f4 [2] 8d ff [2] 96 b1 [2] ab }

  condition:
    any of them
}