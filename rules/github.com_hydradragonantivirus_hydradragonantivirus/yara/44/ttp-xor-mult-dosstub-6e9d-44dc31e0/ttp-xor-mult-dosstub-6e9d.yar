rule TTP_XOR_MULT_DOSStub_6e9d {
  strings:
    $key_6e9d = { 3a f5 [2] 4e ed [2] 09 ef [2] 4e fe [2] 00 f2 [2] 0c f8 [2] 1b f3 [2] 00 bd [2] 3d }

  condition:
    any of them
}