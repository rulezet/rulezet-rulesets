rule TTP_XOR_MULT_DOSStub_2fdd {
  strings:
    $key_2fdd = { 7b b5 [2] 0f ad [2] 48 af [2] 0f be [2] 41 b2 [2] 4d b8 [2] 5a b3 [2] 41 fd [2] 7c }

  condition:
    any of them
}