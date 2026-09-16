rule TTP_XOR_MULT_DOSStub_a88c {
  strings:
    $key_a88c = { fc e4 [2] 88 fc [2] cf fe [2] 88 ef [2] c6 e3 [2] ca e9 [2] dd e2 [2] c6 ac [2] fb }

  condition:
    any of them
}