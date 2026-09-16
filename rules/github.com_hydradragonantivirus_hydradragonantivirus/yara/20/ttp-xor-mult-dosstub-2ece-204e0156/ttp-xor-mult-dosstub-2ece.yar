rule TTP_XOR_MULT_DOSStub_2ece {
  strings:
    $key_2ece = { 7a a6 [2] 0e be [2] 49 bc [2] 0e ad [2] 40 a1 [2] 4c ab [2] 5b a0 [2] 40 ee [2] 7d }

  condition:
    any of them
}