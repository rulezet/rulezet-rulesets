rule TTP_XOR_MULT_DOSStub_299a {
  strings:
    $key_299a = { 7d f2 [2] 09 ea [2] 4e e8 [2] 09 f9 [2] 47 f5 [2] 4b ff [2] 5c f4 [2] 47 ba [2] 7a }

  condition:
    any of them
}