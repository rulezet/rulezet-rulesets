rule TTP_XOR_MULT_DOSStub_aa88 {
  strings:
    $key_aa88 = { fe e0 [2] 8a f8 [2] cd fa [2] 8a eb [2] c4 e7 [2] c8 ed [2] df e6 [2] c4 a8 [2] f9 }

  condition:
    any of them
}