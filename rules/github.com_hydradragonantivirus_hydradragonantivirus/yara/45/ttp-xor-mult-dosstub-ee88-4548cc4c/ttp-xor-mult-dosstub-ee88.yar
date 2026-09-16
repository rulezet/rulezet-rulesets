rule TTP_XOR_MULT_DOSStub_ee88 {
  strings:
    $key_ee88 = { ba e0 [2] ce f8 [2] 89 fa [2] ce eb [2] 80 e7 [2] 8c ed [2] 9b e6 [2] 80 a8 [2] bd }

  condition:
    any of them
}