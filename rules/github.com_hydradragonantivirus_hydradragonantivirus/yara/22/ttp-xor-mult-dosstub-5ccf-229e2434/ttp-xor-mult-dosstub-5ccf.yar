rule TTP_XOR_MULT_DOSStub_5ccf {
  strings:
    $key_5ccf = { 08 a7 [2] 7c bf [2] 3b bd [2] 7c ac [2] 32 a0 [2] 3e aa [2] 29 a1 [2] 32 ef [2] 0f }

  condition:
    any of them
}