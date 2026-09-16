rule TTP_XOR_MULT_DOSStub_299d {
  strings:
    $key_299d = { 7d f5 [2] 09 ed [2] 4e ef [2] 09 fe [2] 47 f2 [2] 4b f8 [2] 5c f3 [2] 47 bd [2] 7a }

  condition:
    any of them
}