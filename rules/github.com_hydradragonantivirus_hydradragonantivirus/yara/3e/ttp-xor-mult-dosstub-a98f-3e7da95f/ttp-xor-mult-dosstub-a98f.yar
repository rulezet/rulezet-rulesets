rule TTP_XOR_MULT_DOSStub_a98f {
  strings:
    $key_a98f = { fd e7 [2] 89 ff [2] ce fd [2] 89 ec [2] c7 e0 [2] cb ea [2] dc e1 [2] c7 af [2] fa }

  condition:
    any of them
}