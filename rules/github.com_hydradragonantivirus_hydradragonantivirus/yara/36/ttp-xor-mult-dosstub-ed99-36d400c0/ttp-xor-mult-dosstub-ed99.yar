rule TTP_XOR_MULT_DOSStub_ed99 {
  strings:
    $key_ed99 = { b9 f1 [2] cd e9 [2] 8a eb [2] cd fa [2] 83 f6 [2] 8f fc [2] 98 f7 [2] 83 b9 [2] be }

  condition:
    any of them
}