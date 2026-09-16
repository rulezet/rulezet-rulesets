rule TTP_XOR_MULT_DOSStub_a881 {
  strings:
    $key_a881 = { fc e9 [2] 88 f1 [2] cf f3 [2] 88 e2 [2] c6 ee [2] ca e4 [2] dd ef [2] c6 a1 [2] fb }

  condition:
    any of them
}