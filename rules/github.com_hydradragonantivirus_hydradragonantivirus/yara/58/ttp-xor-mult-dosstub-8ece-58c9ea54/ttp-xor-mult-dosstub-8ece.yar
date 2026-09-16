rule TTP_XOR_MULT_DOSStub_8ece {
  strings:
    $key_8ece = { da a6 [2] ae be [2] e9 bc [2] ae ad [2] e0 a1 [2] ec ab [2] fb a0 [2] e0 ee [2] dd }

  condition:
    any of them
}