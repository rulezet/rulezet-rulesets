rule TTP_XOR_MULT_DOSStub_299b {
  strings:
    $key_299b = { 7d f3 [2] 09 eb [2] 4e e9 [2] 09 f8 [2] 47 f4 [2] 4b fe [2] 5c f5 [2] 47 bb [2] 7a }

  condition:
    any of them
}