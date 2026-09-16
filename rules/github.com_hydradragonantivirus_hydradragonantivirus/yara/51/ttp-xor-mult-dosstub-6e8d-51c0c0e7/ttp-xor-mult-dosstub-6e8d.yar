rule TTP_XOR_MULT_DOSStub_6e8d {
  strings:
    $key_6e8d = { 3a e5 [2] 4e fd [2] 09 ff [2] 4e ee [2] 00 e2 [2] 0c e8 [2] 1b e3 [2] 00 ad [2] 3d }

  condition:
    any of them
}