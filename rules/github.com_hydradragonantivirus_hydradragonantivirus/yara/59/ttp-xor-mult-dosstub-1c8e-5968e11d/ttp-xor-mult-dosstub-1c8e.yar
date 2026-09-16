rule TTP_XOR_MULT_DOSStub_1c8e {
  strings:
    $key_1c8e = { 48 e6 [2] 3c fe [2] 7b fc [2] 3c ed [2] 72 e1 [2] 7e eb [2] 69 e0 [2] 72 ae [2] 4f }

  condition:
    any of them
}