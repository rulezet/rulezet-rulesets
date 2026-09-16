rule TTP_XOR_MULT_DOSStub_ed91 {
  strings:
    $key_ed91 = { b9 f9 [2] cd e1 [2] 8a e3 [2] cd f2 [2] 83 fe [2] 8f f4 [2] 98 ff [2] 83 b1 [2] be }

  condition:
    any of them
}