rule TTP_XOR_MULT_DOSStub_5acf {
  strings:
    $key_5acf = { 0e a7 [2] 7a bf [2] 3d bd [2] 7a ac [2] 34 a0 [2] 38 aa [2] 2f a1 [2] 34 ef [2] 09 }

  condition:
    any of them
}