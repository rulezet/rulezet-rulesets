rule TTP_XOR_MULT_DOSStub_6bcf {
  strings:
    $key_6bcf = { 3f a7 [2] 4b bf [2] 0c bd [2] 4b ac [2] 05 a0 [2] 09 aa [2] 1e a1 [2] 05 ef [2] 38 }

  condition:
    any of them
}