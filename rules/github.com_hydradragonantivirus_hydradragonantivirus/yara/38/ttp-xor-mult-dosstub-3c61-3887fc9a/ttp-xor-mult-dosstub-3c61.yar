rule TTP_XOR_MULT_DOSStub_3c61 {
  strings:
    $key_3c61 = { 68 09 [2] 1c 11 [2] 5b 13 [2] 1c 02 [2] 52 0e [2] 5e 04 [2] 49 0f [2] 52 41 [2] 6f }

  condition:
    any of them
}