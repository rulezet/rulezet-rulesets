rule TTP_XOR_MULT_DOSStub_dd85 {
  strings:
    $key_dd85 = { 89 ed [2] fd f5 [2] ba f7 [2] fd e6 [2] b3 ea [2] bf e0 [2] a8 eb [2] b3 a5 [2] 8e }

  condition:
    any of them
}