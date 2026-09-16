rule TTP_XOR_MULT_DOSStub_8e9b {
  strings:
    $key_8e9b = { da f3 [2] ae eb [2] e9 e9 [2] ae f8 [2] e0 f4 [2] ec fe [2] fb f5 [2] e0 bb [2] dd }

  condition:
    any of them
}