rule TTP_XOR_MULT_DOSStub_4e8d {
  strings:
    $key_4e8d = { 1a e5 [2] 6e fd [2] 29 ff [2] 6e ee [2] 20 e2 [2] 2c e8 [2] 3b e3 [2] 20 ad [2] 1d }

  condition:
    any of them
}