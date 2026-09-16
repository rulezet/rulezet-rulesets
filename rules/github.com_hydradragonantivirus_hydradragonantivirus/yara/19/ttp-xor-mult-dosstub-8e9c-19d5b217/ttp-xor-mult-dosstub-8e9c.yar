rule TTP_XOR_MULT_DOSStub_8e9c {
  strings:
    $key_8e9c = { da f4 [2] ae ec [2] e9 ee [2] ae ff [2] e0 f3 [2] ec f9 [2] fb f2 [2] e0 bc [2] dd }

  condition:
    any of them
}