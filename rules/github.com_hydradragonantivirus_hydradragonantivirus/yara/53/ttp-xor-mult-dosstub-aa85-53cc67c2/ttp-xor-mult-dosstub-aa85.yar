rule TTP_XOR_MULT_DOSStub_aa85 {
  strings:
    $key_aa85 = { fe ed [2] 8a f5 [2] cd f7 [2] 8a e6 [2] c4 ea [2] c8 e0 [2] df eb [2] c4 a5 [2] f9 }

  condition:
    any of them
}