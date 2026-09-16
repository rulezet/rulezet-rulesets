rule TTP_XOR_MULT_DOSStub_5c8e {
  strings:
    $key_5c8e = { 08 e6 [2] 7c fe [2] 3b fc [2] 7c ed [2] 32 e1 [2] 3e eb [2] 29 e0 [2] 32 ae [2] 0f }

  condition:
    any of them
}