rule TTP_XOR_MULT_DOSStub_7ddd {
  strings:
    $key_7ddd = { 29 b5 [2] 5d ad [2] 1a af [2] 5d be [2] 13 b2 [2] 1f b8 [2] 08 b3 [2] 13 fd [2] 2e }

  condition:
    any of them
}