rule TTP_XOR_MULT_DOSStub_eece {
  strings:
    $key_eece = { ba a6 [2] ce be [2] 89 bc [2] ce ad [2] 80 a1 [2] 8c ab [2] 9b a0 [2] 80 ee [2] bd }

  condition:
    any of them
}