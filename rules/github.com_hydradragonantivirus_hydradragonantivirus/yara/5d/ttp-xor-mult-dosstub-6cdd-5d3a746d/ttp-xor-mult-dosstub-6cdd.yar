rule TTP_XOR_MULT_DOSStub_6cdd {
  strings:
    $key_6cdd = { 38 b5 [2] 4c ad [2] 0b af [2] 4c be [2] 02 b2 [2] 0e b8 [2] 19 b3 [2] 02 fd [2] 3f }

  condition:
    any of them
}