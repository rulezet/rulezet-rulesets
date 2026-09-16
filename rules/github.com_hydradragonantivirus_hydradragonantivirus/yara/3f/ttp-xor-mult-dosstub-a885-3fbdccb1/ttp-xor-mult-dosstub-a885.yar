rule TTP_XOR_MULT_DOSStub_a885 {
  strings:
    $key_a885 = { fc ed [2] 88 f5 [2] cf f7 [2] 88 e6 [2] c6 ea [2] ca e0 [2] dd eb [2] c6 a5 [2] fb }

  condition:
    any of them
}