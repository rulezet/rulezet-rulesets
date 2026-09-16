rule TTP_XOR_MULT_DOSStub_ed81 {
  strings:
    $key_ed81 = { b9 e9 [2] cd f1 [2] 8a f3 [2] cd e2 [2] 83 ee [2] 8f e4 [2] 98 ef [2] 83 a1 [2] be }

  condition:
    any of them
}