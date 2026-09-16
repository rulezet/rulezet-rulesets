rule TTP_XOR_MULT_DOSStub_3edb {
  strings:
    $key_3edb = { 6a b3 [2] 1e ab [2] 59 a9 [2] 1e b8 [2] 50 b4 [2] 5c be [2] 4b b5 [2] 50 fb [2] 6d }

  condition:
    any of them
}