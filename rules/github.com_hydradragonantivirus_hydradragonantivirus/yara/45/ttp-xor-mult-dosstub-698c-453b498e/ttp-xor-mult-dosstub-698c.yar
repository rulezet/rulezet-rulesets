rule TTP_XOR_MULT_DOSStub_698c {
  strings:
    $key_698c = { 3d e4 [2] 49 fc [2] 0e fe [2] 49 ef [2] 07 e3 [2] 0b e9 [2] 1c e2 [2] 07 ac [2] 3a }

  condition:
    any of them
}