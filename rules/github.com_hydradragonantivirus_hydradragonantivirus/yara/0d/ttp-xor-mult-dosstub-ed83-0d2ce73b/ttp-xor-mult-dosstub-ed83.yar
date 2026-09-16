rule TTP_XOR_MULT_DOSStub_ed83 {
  strings:
    $key_ed83 = { b9 eb [2] cd f3 [2] 8a f1 [2] cd e0 [2] 83 ec [2] 8f e6 [2] 98 ed [2] 83 a3 [2] be }

  condition:
    any of them
}