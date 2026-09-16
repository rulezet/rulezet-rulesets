rule TTP_XOR_MULT_DOSStub_4cdd {
  strings:
    $key_4cdd = { 18 b5 [2] 6c ad [2] 2b af [2] 6c be [2] 22 b2 [2] 2e b8 [2] 39 b3 [2] 22 fd [2] 1f }

  condition:
    any of them
}