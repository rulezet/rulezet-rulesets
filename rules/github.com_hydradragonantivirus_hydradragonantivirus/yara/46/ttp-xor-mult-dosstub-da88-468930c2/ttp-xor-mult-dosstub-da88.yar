rule TTP_XOR_MULT_DOSStub_da88 {
  strings:
    $key_da88 = { 8e e0 [2] fa f8 [2] bd fa [2] fa eb [2] b4 e7 [2] b8 ed [2] af e6 [2] b4 a8 [2] 89 }

  condition:
    any of them
}