rule TTP_XOR_MULT_DOSStub_2c8e {
  strings:
    $key_2c8e = { 78 e6 [2] 0c fe [2] 4b fc [2] 0c ed [2] 42 e1 [2] 4e eb [2] 59 e0 [2] 42 ae [2] 7f }

  condition:
    any of them
}