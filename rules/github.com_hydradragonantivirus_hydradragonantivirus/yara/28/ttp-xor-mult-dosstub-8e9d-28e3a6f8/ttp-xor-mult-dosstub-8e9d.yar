rule TTP_XOR_MULT_DOSStub_8e9d {
  strings:
    $key_8e9d = { da f5 [2] ae ed [2] e9 ef [2] ae fe [2] e0 f2 [2] ec f8 [2] fb f3 [2] e0 bd [2] dd }

  condition:
    any of them
}