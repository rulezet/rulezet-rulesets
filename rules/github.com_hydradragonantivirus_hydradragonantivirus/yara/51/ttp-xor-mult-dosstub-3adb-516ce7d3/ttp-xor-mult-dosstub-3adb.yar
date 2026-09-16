rule TTP_XOR_MULT_DOSStub_3adb {
  strings:
    $key_3adb = { 6e b3 [2] 1a ab [2] 5d a9 [2] 1a b8 [2] 54 b4 [2] 58 be [2] 4f b5 [2] 54 fb [2] 69 }

  condition:
    any of them
}