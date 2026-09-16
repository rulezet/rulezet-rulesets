rule TTP_XOR_MULT_DOSStub_1edb {
  strings:
    $key_1edb = { 4a b3 [2] 3e ab [2] 79 a9 [2] 3e b8 [2] 70 b4 [2] 7c be [2] 6b b5 [2] 70 fb [2] 4d }

  condition:
    any of them
}