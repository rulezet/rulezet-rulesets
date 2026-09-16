rule TTP_XOR_MULT_DOSStub_edca {
  strings:
    $key_edca = { b9 a2 [2] cd ba [2] 8a b8 [2] cd a9 [2] 83 a5 [2] 8f af [2] 98 a4 [2] 83 ea [2] be }

  condition:
    any of them
}