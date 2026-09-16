rule TTP_XOR_MULT_DOSStub_4961 {
  strings:
    $key_4961 = { 1d 09 [2] 69 11 [2] 2e 13 [2] 69 02 [2] 27 0e [2] 2b 04 [2] 3c 0f [2] 27 41 [2] 1a }

  condition:
    any of them
}