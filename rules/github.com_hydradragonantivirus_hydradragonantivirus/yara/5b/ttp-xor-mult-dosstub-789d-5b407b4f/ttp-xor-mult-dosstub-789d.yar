rule TTP_XOR_MULT_DOSStub_789d {
  strings:
    $key_789d = { 2c f5 [2] 58 ed [2] 1f ef [2] 58 fe [2] 16 f2 [2] 1a f8 [2] 0d f3 [2] 16 bd [2] 2b }

  condition:
    any of them
}