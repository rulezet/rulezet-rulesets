rule TTP_XOR_MULT_DOSStub_6ecf {
  strings:
    $key_6ecf = { 3a a7 [2] 4e bf [2] 09 bd [2] 4e ac [2] 00 a0 [2] 0c aa [2] 1b a1 [2] 00 ef [2] 3d }

  condition:
    any of them
}