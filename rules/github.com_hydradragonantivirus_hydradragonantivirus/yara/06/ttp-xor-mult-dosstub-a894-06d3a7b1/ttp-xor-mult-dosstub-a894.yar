rule TTP_XOR_MULT_DOSStub_a894 {
  strings:
    $key_a894 = { fc fc [2] 88 e4 [2] cf e6 [2] 88 f7 [2] c6 fb [2] ca f1 [2] dd fa [2] c6 b4 [2] fb }

  condition:
    any of them
}