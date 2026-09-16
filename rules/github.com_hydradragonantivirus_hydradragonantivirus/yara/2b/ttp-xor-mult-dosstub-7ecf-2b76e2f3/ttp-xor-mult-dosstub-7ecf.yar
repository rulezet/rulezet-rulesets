rule TTP_XOR_MULT_DOSStub_7ecf {
  strings:
    $key_7ecf = { 2a a7 [2] 5e bf [2] 19 bd [2] 5e ac [2] 10 a0 [2] 1c aa [2] 0b a1 [2] 10 ef [2] 2d }

  condition:
    any of them
}