rule TTP_XOR_MULT_DOSStub_c485 {
  strings:
    $key_c485 = { 90 ed [2] e4 f5 [2] a3 f7 [2] e4 e6 [2] aa ea [2] a6 e0 [2] b1 eb [2] aa a5 [2] 97 }

  condition:
    any of them
}