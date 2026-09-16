rule TTP_XOR_MULT_DOSStub_488c {
  strings:
    $key_488c = { 1c e4 [2] 68 fc [2] 2f fe [2] 68 ef [2] 26 e3 [2] 2a e9 [2] 3d e2 [2] 26 ac [2] 1b }

  condition:
    any of them
}