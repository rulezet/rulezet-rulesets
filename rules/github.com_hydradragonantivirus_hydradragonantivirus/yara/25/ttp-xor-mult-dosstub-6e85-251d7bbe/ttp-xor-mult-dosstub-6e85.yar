rule TTP_XOR_MULT_DOSStub_6e85 {
  strings:
    $key_6e85 = { 3a ed [2] 4e f5 [2] 09 f7 [2] 4e e6 [2] 00 ea [2] 0c e0 [2] 1b eb [2] 00 a5 [2] 3d }

  condition:
    any of them
}