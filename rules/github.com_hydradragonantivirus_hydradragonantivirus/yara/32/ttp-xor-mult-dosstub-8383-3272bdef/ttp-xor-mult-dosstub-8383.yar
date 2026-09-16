rule TTP_XOR_MULT_DOSStub_8383 {
  strings:
    $key_8383 = { d7 eb [2] a3 f3 [2] e4 f1 [2] a3 e0 [2] ed ec [2] e1 e6 [2] f6 ed [2] ed a3 [2] d0 }

  condition:
    any of them
}