rule TTP_XOR_MULT_DOSStub_8eab {
  strings:
    $key_8eab = { da c3 [2] ae db [2] e9 d9 [2] ae c8 [2] e0 c4 [2] ec ce [2] fb c5 [2] e0 8b [2] dd }

  condition:
    any of them
}