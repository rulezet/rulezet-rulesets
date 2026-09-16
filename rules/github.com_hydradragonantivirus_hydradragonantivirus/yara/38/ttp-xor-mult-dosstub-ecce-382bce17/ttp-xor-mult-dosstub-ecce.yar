rule TTP_XOR_MULT_DOSStub_ecce {
  strings:
    $key_ecce = { b8 a6 [2] cc be [2] 8b bc [2] cc ad [2] 82 a1 [2] 8e ab [2] 99 a0 [2] 82 ee [2] bf }

  condition:
    any of them
}