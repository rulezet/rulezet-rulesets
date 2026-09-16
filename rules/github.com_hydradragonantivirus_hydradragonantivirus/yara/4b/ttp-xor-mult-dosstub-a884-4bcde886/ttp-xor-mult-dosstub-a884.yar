rule TTP_XOR_MULT_DOSStub_a884 {
  strings:
    $key_a884 = { fc ec [2] 88 f4 [2] cf f6 [2] 88 e7 [2] c6 eb [2] ca e1 [2] dd ea [2] c6 a4 [2] fb }

  condition:
    any of them
}