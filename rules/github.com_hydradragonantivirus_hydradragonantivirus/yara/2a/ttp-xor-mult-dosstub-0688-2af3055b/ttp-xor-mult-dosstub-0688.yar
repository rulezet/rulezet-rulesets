rule TTP_XOR_MULT_DOSStub_0688 {
  strings:
    $key_0688 = { 52 e0 [2] 26 f8 [2] 61 fa [2] 26 eb [2] 68 e7 [2] 64 ed [2] 73 e6 [2] 68 a8 [2] 55 }

  condition:
    any of them
}