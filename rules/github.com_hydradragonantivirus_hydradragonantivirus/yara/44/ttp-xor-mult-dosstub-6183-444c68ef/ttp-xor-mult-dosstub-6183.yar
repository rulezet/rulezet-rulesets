rule TTP_XOR_MULT_DOSStub_6183 {
  strings:
    $key_6183 = { 35 eb [2] 41 f3 [2] 06 f1 [2] 41 e0 [2] 0f ec [2] 03 e6 [2] 14 ed [2] 0f a3 [2] 32 }

  condition:
    any of them
}