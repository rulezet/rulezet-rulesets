rule TTP_XOR_MULT_DOSStub_3c8e {
  strings:
    $key_3c8e = { 68 e6 [2] 1c fe [2] 5b fc [2] 1c ed [2] 52 e1 [2] 5e eb [2] 49 e0 [2] 52 ae [2] 6f }

  condition:
    any of them
}