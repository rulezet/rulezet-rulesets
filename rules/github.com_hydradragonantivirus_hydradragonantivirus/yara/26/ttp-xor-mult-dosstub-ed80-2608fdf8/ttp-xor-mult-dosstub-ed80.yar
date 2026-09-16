rule TTP_XOR_MULT_DOSStub_ed80 {
  strings:
    $key_ed80 = { b9 e8 [2] cd f0 [2] 8a f2 [2] cd e3 [2] 83 ef [2] 8f e5 [2] 98 ee [2] 83 a0 [2] be }

  condition:
    any of them
}