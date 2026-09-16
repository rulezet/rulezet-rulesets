rule TTP_XOR_MULT_DOSStub_ed82 {
  strings:
    $key_ed82 = { b9 ea [2] cd f2 [2] 8a f0 [2] cd e1 [2] 83 ed [2] 8f e7 [2] 98 ec [2] 83 a2 [2] be }

  condition:
    any of them
}