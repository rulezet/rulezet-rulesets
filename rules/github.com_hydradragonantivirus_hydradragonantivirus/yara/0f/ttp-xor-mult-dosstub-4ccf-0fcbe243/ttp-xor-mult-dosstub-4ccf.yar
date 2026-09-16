rule TTP_XOR_MULT_DOSStub_4ccf {
  strings:
    $key_4ccf = { 18 a7 [2] 6c bf [2] 2b bd [2] 6c ac [2] 22 a0 [2] 2e aa [2] 39 a1 [2] 22 ef [2] 1f }

  condition:
    any of them
}