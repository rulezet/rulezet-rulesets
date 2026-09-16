rule TTP_XOR_MULT_DOSStub_1e9d {
  strings:
    $key_1e9d = { 4a f5 [2] 3e ed [2] 79 ef [2] 3e fe [2] 70 f2 [2] 7c f8 [2] 6b f3 [2] 70 bd [2] 4d }

  condition:
    any of them
}