rule TTP_XOR_MULT_DOSStub_f88e {
  strings:
    $key_f88e = { ac e6 [2] d8 fe [2] 9f fc [2] d8 ed [2] 96 e1 [2] 9a eb [2] 8d e0 [2] 96 ae [2] ab }

  condition:
    any of them
}