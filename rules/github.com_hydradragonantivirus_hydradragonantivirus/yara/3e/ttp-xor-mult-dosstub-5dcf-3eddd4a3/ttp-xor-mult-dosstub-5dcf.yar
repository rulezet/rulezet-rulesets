rule TTP_XOR_MULT_DOSStub_5dcf {
  strings:
    $key_5dcf = { 09 a7 [2] 7d bf [2] 3a bd [2] 7d ac [2] 33 a0 [2] 3f aa [2] 28 a1 [2] 33 ef [2] 0e }

  condition:
    any of them
}