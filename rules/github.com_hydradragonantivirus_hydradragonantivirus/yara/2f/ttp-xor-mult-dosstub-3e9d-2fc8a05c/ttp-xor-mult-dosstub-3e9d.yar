rule TTP_XOR_MULT_DOSStub_3e9d {
  strings:
    $key_3e9d = { 6a f5 [2] 1e ed [2] 59 ef [2] 1e fe [2] 50 f2 [2] 5c f8 [2] 4b f3 [2] 50 bd [2] 6d }

  condition:
    any of them
}