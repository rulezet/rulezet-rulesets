rule TTP_XOR_MULT_DOSStub_fadf {
  strings:
    $key_fadf = { ae b7 [2] da af [2] 9d ad [2] da bc [2] 94 b0 [2] 98 ba [2] 8f b1 [2] 94 ff [2] a9 }

  condition:
    any of them
}