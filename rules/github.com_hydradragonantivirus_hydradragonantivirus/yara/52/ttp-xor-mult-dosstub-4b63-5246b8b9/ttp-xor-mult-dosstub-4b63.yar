rule TTP_XOR_MULT_DOSStub_4b63 {
  strings:
    $key_4b63 = { 1f 0b [2] 6b 13 [2] 2c 11 [2] 6b 00 [2] 25 0c [2] 29 06 [2] 3e 0d [2] 25 43 [2] 18 }

  condition:
    any of them
}