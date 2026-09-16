rule TTP_XOR_MULT_DOSStub_5adb {
  strings:
    $key_5adb = { 0e b3 [2] 7a ab [2] 3d a9 [2] 7a b8 [2] 34 b4 [2] 38 be [2] 2f b5 [2] 34 fb [2] 09 }

  condition:
    any of them
}