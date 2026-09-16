rule TTP_XOR_MULT_DOSStub_5cdd {
  strings:
    $key_5cdd = { 08 b5 [2] 7c ad [2] 3b af [2] 7c be [2] 32 b2 [2] 3e b8 [2] 29 b3 [2] 32 fd [2] 0f }

  condition:
    any of them
}