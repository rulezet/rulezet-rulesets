rule TTP_XOR_MULT_DOSStub_dccf {
  strings:
    $key_dccf = { 88 a7 [2] fc bf [2] bb bd [2] fc ac [2] b2 a0 [2] be aa [2] a9 a1 [2] b2 ef [2] 8f }

  condition:
    any of them
}