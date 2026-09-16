rule TTP_XOR_MULT_DOSStub_3fcf {
  strings:
    $key_3fcf = { 6b a7 [2] 1f bf [2] 58 bd [2] 1f ac [2] 51 a0 [2] 5d aa [2] 4a a1 [2] 51 ef [2] 6c }

  condition:
    any of them
}