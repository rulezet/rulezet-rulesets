rule TTP_XOR_MULT_DOSStub_ed9a {
  strings:
    $key_ed9a = { b9 f2 [2] cd ea [2] 8a e8 [2] cd f9 [2] 83 f5 [2] 8f ff [2] 98 f4 [2] 83 ba [2] be }

  condition:
    any of them
}