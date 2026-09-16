rule TTP_XOR_MULT_DOSStub_6580 {
  strings:
    $key_6580 = { 31 e8 [2] 45 f0 [2] 02 f2 [2] 45 e3 [2] 0b ef [2] 07 e5 [2] 10 ee [2] 0b a0 [2] 36 }

  condition:
    any of them
}