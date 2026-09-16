rule TTP_XOR_MULT_DOSStub_2788 {
  strings:
    $key_2788 = { 73 e0 [2] 07 f8 [2] 40 fa [2] 07 eb [2] 49 e7 [2] 45 ed [2] 52 e6 [2] 49 a8 [2] 74 }

  condition:
    any of them
}