rule TTP_XOR_MULT_DOSStub_6fcf {
  strings:
    $key_6fcf = { 3b a7 [2] 4f bf [2] 08 bd [2] 4f ac [2] 01 a0 [2] 0d aa [2] 1a a1 [2] 01 ef [2] 3c }

  condition:
    any of them
}