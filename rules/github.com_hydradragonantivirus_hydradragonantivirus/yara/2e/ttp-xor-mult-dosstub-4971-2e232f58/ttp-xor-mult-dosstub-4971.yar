rule TTP_XOR_MULT_DOSStub_4971 {
  strings:
    $key_4971 = { 1d 19 [2] 69 01 [2] 2e 03 [2] 69 12 [2] 27 1e [2] 2b 14 [2] 3c 1f [2] 27 51 [2] 1a }

  condition:
    any of them
}