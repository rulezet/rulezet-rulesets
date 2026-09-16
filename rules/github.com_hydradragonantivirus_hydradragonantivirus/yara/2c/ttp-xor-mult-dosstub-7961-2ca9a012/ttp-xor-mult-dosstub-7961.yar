rule TTP_XOR_MULT_DOSStub_7961 {
  strings:
    $key_7961 = { 2d 09 [2] 59 11 [2] 1e 13 [2] 59 02 [2] 17 0e [2] 1b 04 [2] 0c 0f [2] 17 41 [2] 2a }

  condition:
    any of them
}