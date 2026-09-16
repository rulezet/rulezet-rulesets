rule TTP_XOR_MULT_DOSStub_2adb {
  strings:
    $key_2adb = { 7e b3 [2] 0a ab [2] 4d a9 [2] 0a b8 [2] 44 b4 [2] 48 be [2] 5f b5 [2] 44 fb [2] 79 }

  condition:
    any of them
}