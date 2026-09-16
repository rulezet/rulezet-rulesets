rule TTP_XOR_MULT_DOSStub_5ddd {
  strings:
    $key_5ddd = { 09 b5 [2] 7d ad [2] 3a af [2] 7d be [2] 33 b2 [2] 3f b8 [2] 28 b3 [2] 33 fd [2] 0e }

  condition:
    any of them
}