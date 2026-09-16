rule TTP_XOR_MULT_DOSStub_3cdd {
  strings:
    $key_3cdd = { 68 b5 [2] 1c ad [2] 5b af [2] 1c be [2] 52 b2 [2] 5e b8 [2] 49 b3 [2] 52 fd [2] 6f }

  condition:
    any of them
}