rule TTP_XOR_MULT_DOSStub_ed96 {
  strings:
    $key_ed96 = { b9 fe [2] cd e6 [2] 8a e4 [2] cd f5 [2] 83 f9 [2] 8f f3 [2] 98 f8 [2] 83 b6 [2] be }

  condition:
    any of them
}