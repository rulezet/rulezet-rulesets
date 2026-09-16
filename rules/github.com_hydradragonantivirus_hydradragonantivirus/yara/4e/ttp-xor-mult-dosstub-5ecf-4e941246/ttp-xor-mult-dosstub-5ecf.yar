rule TTP_XOR_MULT_DOSStub_5ecf {
  strings:
    $key_5ecf = { 0a a7 [2] 7e bf [2] 39 bd [2] 7e ac [2] 30 a0 [2] 3c aa [2] 2b a1 [2] 30 ef [2] 0d }

  condition:
    any of them
}