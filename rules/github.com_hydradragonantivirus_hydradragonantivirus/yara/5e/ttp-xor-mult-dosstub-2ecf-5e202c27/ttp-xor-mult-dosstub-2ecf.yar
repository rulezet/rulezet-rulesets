rule TTP_XOR_MULT_DOSStub_2ecf {
  strings:
    $key_2ecf = { 7a a7 [2] 0e bf [2] 49 bd [2] 0e ac [2] 40 a0 [2] 4c aa [2] 5b a1 [2] 40 ef [2] 7d }

  condition:
    any of them
}