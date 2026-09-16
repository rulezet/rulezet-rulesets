rule TTP_XOR_MULT_DOSStub_4c61 {
  strings:
    $key_4c61 = { 18 09 [2] 6c 11 [2] 2b 13 [2] 6c 02 [2] 22 0e [2] 2e 04 [2] 39 0f [2] 22 41 [2] 1f }

  condition:
    any of them
}