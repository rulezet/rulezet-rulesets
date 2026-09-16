rule TTP_XOR_MULT_DOSStub_6e9a {
  strings:
    $key_6e9a = { 3a f2 [2] 4e ea [2] 09 e8 [2] 4e f9 [2] 00 f5 [2] 0c ff [2] 1b f4 [2] 00 ba [2] 3d }

  condition:
    any of them
}