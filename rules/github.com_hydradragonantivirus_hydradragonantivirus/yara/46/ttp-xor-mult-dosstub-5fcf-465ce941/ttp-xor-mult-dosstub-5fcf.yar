rule TTP_XOR_MULT_DOSStub_5fcf {
  strings:
    $key_5fcf = { 0b a7 [2] 7f bf [2] 38 bd [2] 7f ac [2] 31 a0 [2] 3d aa [2] 2a a1 [2] 31 ef [2] 0c }

  condition:
    any of them
}