rule TTP_XOR_MULT_DOSStub_8e9f {
  strings:
    $key_8e9f = { da f7 [2] ae ef [2] e9 ed [2] ae fc [2] e0 f0 [2] ec fa [2] fb f1 [2] e0 bf [2] dd }

  condition:
    any of them
}