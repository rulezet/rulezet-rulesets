rule TTP_XOR_MULT_DOSStub_f688 {
  strings:
    $key_f688 = { a2 e0 [2] d6 f8 [2] 91 fa [2] d6 eb [2] 98 e7 [2] 94 ed [2] 83 e6 [2] 98 a8 [2] a5 }

  condition:
    any of them
}