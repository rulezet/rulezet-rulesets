rule TTP_XOR_MULT_DOSStub_3ccf {
  strings:
    $key_3ccf = { 68 a7 [2] 1c bf [2] 5b bd [2] 1c ac [2] 52 a0 [2] 5e aa [2] 49 a1 [2] 52 ef [2] 6f }

  condition:
    any of them
}