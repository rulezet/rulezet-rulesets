rule TTP_XOR_MULT_DOSStub_0ecf {
  strings:
    $key_0ecf = { 5a a7 [2] 2e bf [2] 69 bd [2] 2e ac [2] 60 a0 [2] 6c aa [2] 7b a1 [2] 60 ef [2] 5d }

  condition:
    any of them
}