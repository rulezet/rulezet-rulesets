rule TTP_XOR_MULT_DOSStub_cd88 {
  strings:
    $key_cd88 = { 99 e0 [2] ed f8 [2] aa fa [2] ed eb [2] a3 e7 [2] af ed [2] b8 e6 [2] a3 a8 [2] 9e }

  condition:
    any of them
}