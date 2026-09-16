rule TTP_XOR_MULT_DOSStub_a893 {
  strings:
    $key_a893 = { fc fb [2] 88 e3 [2] cf e1 [2] 88 f0 [2] c6 fc [2] ca f6 [2] dd fd [2] c6 b3 [2] fb }

  condition:
    any of them
}