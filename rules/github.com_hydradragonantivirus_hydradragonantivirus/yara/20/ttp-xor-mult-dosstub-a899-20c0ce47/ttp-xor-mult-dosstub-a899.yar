rule TTP_XOR_MULT_DOSStub_a899 {
  strings:
    $key_a899 = { fc f1 [2] 88 e9 [2] cf eb [2] 88 fa [2] c6 f6 [2] ca fc [2] dd f7 [2] c6 b9 [2] fb }

  condition:
    any of them
}