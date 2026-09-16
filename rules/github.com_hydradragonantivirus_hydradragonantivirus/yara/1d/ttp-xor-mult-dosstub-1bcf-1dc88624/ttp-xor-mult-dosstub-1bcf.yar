rule TTP_XOR_MULT_DOSStub_1bcf {
  strings:
    $key_1bcf = { 4f a7 [2] 3b bf [2] 7c bd [2] 3b ac [2] 75 a0 [2] 79 aa [2] 6e a1 [2] 75 ef [2] 48 }

  condition:
    any of them
}