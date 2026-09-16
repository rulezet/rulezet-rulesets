rule TTP_XOR_MULT_DOSStub_4ddd {
  strings:
    $key_4ddd = { 19 b5 [2] 6d ad [2] 2a af [2] 6d be [2] 23 b2 [2] 2f b8 [2] 38 b3 [2] 23 fd [2] 1e }

  condition:
    any of them
}