rule TTP_XOR_MULT_DOSStub_fa88 {
  strings:
    $key_fa88 = { ae e0 [2] da f8 [2] 9d fa [2] da eb [2] 94 e7 [2] 98 ed [2] 8f e6 [2] 94 a8 [2] a9 }

  condition:
    any of them
}