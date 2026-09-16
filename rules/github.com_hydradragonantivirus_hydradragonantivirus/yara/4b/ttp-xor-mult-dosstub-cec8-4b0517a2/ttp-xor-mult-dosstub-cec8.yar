rule TTP_XOR_MULT_DOSStub_cec8 {
  strings:
    $key_cec8 = { 9a a0 [2] ee b8 [2] a9 ba [2] ee ab [2] a0 a7 [2] ac ad [2] bb a6 [2] a0 e8 [2] 9d }

  condition:
    any of them
}