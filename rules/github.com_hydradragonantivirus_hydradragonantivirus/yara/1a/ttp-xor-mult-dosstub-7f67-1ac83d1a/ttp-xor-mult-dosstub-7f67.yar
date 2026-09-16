rule TTP_XOR_MULT_DOSStub_7f67 {
  strings:
    $key_7f67 = { 2b 0f [2] 5f 17 [2] 18 15 [2] 5f 04 [2] 11 08 [2] 1d 02 [2] 0a 09 [2] 11 47 [2] 2c }

  condition:
    any of them
}