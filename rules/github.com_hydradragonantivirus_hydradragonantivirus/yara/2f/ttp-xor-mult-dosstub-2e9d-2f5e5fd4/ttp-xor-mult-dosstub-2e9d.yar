rule TTP_XOR_MULT_DOSStub_2e9d {
  strings:
    $key_2e9d = { 7a f5 [2] 0e ed [2] 49 ef [2] 0e fe [2] 40 f2 [2] 4c f8 [2] 5b f3 [2] 40 bd [2] 7d }

  condition:
    any of them
}