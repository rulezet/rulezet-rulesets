rule TTP_XOR_MULT_DOSStub_5e8d {
  strings:
    $key_5e8d = { 0a e5 [2] 7e fd [2] 39 ff [2] 7e ee [2] 30 e2 [2] 3c e8 [2] 2b e3 [2] 30 ad [2] 0d }

  condition:
    any of them
}