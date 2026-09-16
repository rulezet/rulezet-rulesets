rule TTP_XOR_MULT_DOSStub_fb88 {
  strings:
    $key_fb88 = { af e0 [2] db f8 [2] 9c fa [2] db eb [2] 95 e7 [2] 99 ed [2] 8e e6 [2] 95 a8 [2] a8 }

  condition:
    any of them
}