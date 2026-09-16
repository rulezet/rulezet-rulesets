rule TTP_XOR_MULT_DOSStub_7dcf {
  strings:
    $key_7dcf = { 29 a7 [2] 5d bf [2] 1a bd [2] 5d ac [2] 13 a0 [2] 1f aa [2] 08 a1 [2] 13 ef [2] 2e }

  condition:
    any of them
}