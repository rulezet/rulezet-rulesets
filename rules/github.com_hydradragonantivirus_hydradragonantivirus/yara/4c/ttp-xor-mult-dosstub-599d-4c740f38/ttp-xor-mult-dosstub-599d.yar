rule TTP_XOR_MULT_DOSStub_599d {
  strings:
    $key_599d = { 0d f5 [2] 79 ed [2] 3e ef [2] 79 fe [2] 37 f2 [2] 3b f8 [2] 2c f3 [2] 37 bd [2] 0a }

  condition:
    any of them
}