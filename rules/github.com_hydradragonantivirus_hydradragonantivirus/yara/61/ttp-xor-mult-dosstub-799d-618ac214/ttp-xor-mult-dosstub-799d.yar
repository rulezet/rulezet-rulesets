rule TTP_XOR_MULT_DOSStub_799d {
  strings:
    $key_799d = { 2d f5 [2] 59 ed [2] 1e ef [2] 59 fe [2] 17 f2 [2] 1b f8 [2] 0c f3 [2] 17 bd [2] 2a }

  condition:
    any of them
}