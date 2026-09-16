rule TTP_XOR_MULT_DOSStub_ed97 {
  strings:
    $key_ed97 = { b9 ff [2] cd e7 [2] 8a e5 [2] cd f4 [2] 83 f8 [2] 8f f2 [2] 98 f9 [2] 83 b7 [2] be }

  condition:
    any of them
}