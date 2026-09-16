rule TTP_XOR_MULT_DOSStub_aa9b {
  strings:
    $key_aa9b = { fe f3 [2] 8a eb [2] cd e9 [2] 8a f8 [2] c4 f4 [2] c8 fe [2] df f5 [2] c4 bb [2] f9 }

  condition:
    any of them
}