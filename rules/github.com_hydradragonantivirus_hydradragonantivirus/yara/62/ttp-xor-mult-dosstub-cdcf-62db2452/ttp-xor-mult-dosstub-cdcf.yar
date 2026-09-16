rule TTP_XOR_MULT_DOSStub_cdcf {
  strings:
    $key_cdcf = { 99 a7 [2] ed bf [2] aa bd [2] ed ac [2] a3 a0 [2] af aa [2] b8 a1 [2] a3 ef [2] 9e }

  condition:
    any of them
}