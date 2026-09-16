rule TTP_XOR_MULT_DOSStub_a883 {
  strings:
    $key_a883 = { fc eb [2] 88 f3 [2] cf f1 [2] 88 e0 [2] c6 ec [2] ca e6 [2] dd ed [2] c6 a3 [2] fb }

  condition:
    any of them
}