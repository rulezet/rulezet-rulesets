rule TTP_XOR_MULT_DOSStub_ed94 {
  strings:
    $key_ed94 = { b9 fc [2] cd e4 [2] 8a e6 [2] cd f7 [2] 83 fb [2] 8f f1 [2] 98 fa [2] 83 b4 [2] be }

  condition:
    any of them
}