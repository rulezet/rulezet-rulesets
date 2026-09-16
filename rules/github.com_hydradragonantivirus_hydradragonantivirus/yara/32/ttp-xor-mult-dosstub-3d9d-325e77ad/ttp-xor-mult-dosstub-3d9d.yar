rule TTP_XOR_MULT_DOSStub_3d9d {
  strings:
    $key_3d9d = { 69 f5 [2] 1d ed [2] 5a ef [2] 1d fe [2] 53 f2 [2] 5f f8 [2] 48 f3 [2] 53 bd [2] 6e }

  condition:
    any of them
}