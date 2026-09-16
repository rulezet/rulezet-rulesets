rule TTP_XOR_MULT_DOSStub_fc8f {
  strings:
    $key_fc8f = { a8 e7 [2] dc ff [2] 9b fd [2] dc ec [2] 92 e0 [2] 9e ea [2] 89 e1 [2] 92 af [2] af }

  condition:
    any of them
}