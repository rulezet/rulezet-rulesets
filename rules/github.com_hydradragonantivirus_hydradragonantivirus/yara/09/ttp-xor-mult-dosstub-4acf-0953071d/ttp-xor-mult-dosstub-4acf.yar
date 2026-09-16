rule TTP_XOR_MULT_DOSStub_4acf {
  strings:
    $key_4acf = { 1e a7 [2] 6a bf [2] 2d bd [2] 6a ac [2] 24 a0 [2] 28 aa [2] 3f a1 [2] 24 ef [2] 19 }

  condition:
    any of them
}