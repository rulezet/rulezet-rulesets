rule TTP_XOR_MULT_DOSStub_5ddb {
  strings:
    $key_5ddb = { 09 b3 [2] 7d ab [2] 3a a9 [2] 7d b8 [2] 33 b4 [2] 3f be [2] 28 b5 [2] 33 fb [2] 0e }

  condition:
    any of them
}