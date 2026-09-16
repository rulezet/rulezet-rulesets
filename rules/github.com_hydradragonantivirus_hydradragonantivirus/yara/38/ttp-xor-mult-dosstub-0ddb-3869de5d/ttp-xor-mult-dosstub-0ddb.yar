rule TTP_XOR_MULT_DOSStub_0ddb {
  strings:
    $key_0ddb = { 59 b3 [2] 2d ab [2] 6a a9 [2] 2d b8 [2] 63 b4 [2] 6f be [2] 78 b5 [2] 63 fb [2] 5e }

  condition:
    any of them
}