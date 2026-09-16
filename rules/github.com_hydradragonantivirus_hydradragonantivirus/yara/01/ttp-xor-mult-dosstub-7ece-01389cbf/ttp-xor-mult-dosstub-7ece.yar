rule TTP_XOR_MULT_DOSStub_7ece {
  strings:
    $key_7ece = { 2a a6 [2] 5e be [2] 19 bc [2] 5e ad [2] 10 a1 [2] 1c ab [2] 0b a0 [2] 10 ee [2] 2d }

  condition:
    any of them
}