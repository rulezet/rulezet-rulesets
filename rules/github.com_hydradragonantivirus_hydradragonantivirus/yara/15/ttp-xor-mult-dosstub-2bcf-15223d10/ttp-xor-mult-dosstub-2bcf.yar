rule TTP_XOR_MULT_DOSStub_2bcf {
  strings:
    $key_2bcf = { 7f a7 [2] 0b bf [2] 4c bd [2] 0b ac [2] 45 a0 [2] 49 aa [2] 5e a1 [2] 45 ef [2] 78 }

  condition:
    any of them
}