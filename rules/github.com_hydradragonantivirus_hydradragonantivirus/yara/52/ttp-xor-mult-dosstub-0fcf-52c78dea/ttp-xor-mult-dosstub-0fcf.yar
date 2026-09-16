rule TTP_XOR_MULT_DOSStub_0fcf {
  strings:
    $key_0fcf = { 5b a7 [2] 2f bf [2] 68 bd [2] 2f ac [2] 61 a0 [2] 6d aa [2] 7a a1 [2] 61 ef [2] 5c }

  condition:
    any of them
}