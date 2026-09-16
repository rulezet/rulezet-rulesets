rule TTP_XOR_MULT_DOSStub_898c {
  strings:
    $key_898c = { dd e4 [2] a9 fc [2] ee fe [2] a9 ef [2] e7 e3 [2] eb e9 [2] fc e2 [2] e7 ac [2] da }

  condition:
    any of them
}