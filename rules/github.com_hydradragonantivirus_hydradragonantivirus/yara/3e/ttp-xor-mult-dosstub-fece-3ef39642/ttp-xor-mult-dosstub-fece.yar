rule TTP_XOR_MULT_DOSStub_fece {
  strings:
    $key_fece = { aa a6 [2] de be [2] 99 bc [2] de ad [2] 90 a1 [2] 9c ab [2] 8b a0 [2] 90 ee [2] ad }

  condition:
    any of them
}