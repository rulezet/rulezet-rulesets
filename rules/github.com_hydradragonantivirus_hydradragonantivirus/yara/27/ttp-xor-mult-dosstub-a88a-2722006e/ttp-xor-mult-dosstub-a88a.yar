rule TTP_XOR_MULT_DOSStub_a88a {
  strings:
    $key_a88a = { fc e2 [2] 88 fa [2] cf f8 [2] 88 e9 [2] c6 e5 [2] ca ef [2] dd e4 [2] c6 aa [2] fb }

  condition:
    any of them
}