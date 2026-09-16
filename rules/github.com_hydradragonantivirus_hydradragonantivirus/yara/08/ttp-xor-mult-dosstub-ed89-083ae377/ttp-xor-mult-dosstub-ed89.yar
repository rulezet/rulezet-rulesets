rule TTP_XOR_MULT_DOSStub_ed89 {
  strings:
    $key_ed89 = { b9 e1 [2] cd f9 [2] 8a fb [2] cd ea [2] 83 e6 [2] 8f ec [2] 98 e7 [2] 83 a9 [2] be }

  condition:
    any of them
}