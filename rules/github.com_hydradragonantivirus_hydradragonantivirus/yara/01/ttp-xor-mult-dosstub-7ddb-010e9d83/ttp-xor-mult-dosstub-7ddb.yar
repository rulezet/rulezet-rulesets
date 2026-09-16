rule TTP_XOR_MULT_DOSStub_7ddb {
  strings:
    $key_7ddb = { 29 b3 [2] 5d ab [2] 1a a9 [2] 5d b8 [2] 13 b4 [2] 1f be [2] 08 b5 [2] 13 fb [2] 2e }

  condition:
    any of them
}