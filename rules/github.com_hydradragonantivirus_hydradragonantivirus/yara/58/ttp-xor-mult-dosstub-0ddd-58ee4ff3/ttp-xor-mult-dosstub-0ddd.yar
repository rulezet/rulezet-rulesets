rule TTP_XOR_MULT_DOSStub_0ddd {
  strings:
    $key_0ddd = { 59 b5 [2] 2d ad [2] 6a af [2] 2d be [2] 63 b2 [2] 6f b8 [2] 78 b3 [2] 63 fd [2] 5e }

  condition:
    any of them
}