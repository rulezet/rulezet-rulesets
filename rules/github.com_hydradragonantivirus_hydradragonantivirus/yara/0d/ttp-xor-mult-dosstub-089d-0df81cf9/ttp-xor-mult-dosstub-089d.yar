rule TTP_XOR_MULT_DOSStub_089d {
  strings:
    $key_089d = { 5c f5 [2] 28 ed [2] 6f ef [2] 28 fe [2] 66 f2 [2] 6a f8 [2] 7d f3 [2] 66 bd [2] 5b }

  condition:
    any of them
}