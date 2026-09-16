rule TTP_XOR_MULT_DOSStub_7fe0 {
  strings:
    $key_7fe0 = { 2b 88 [2] 5f 90 [2] 18 92 [2] 5f 83 [2] 11 8f [2] 1d 85 [2] 0a 8e [2] 11 c0 [2] 2c }

  condition:
    any of them
}