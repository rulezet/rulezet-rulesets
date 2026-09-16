rule TTP_XOR_MULT_DOSStub_7f04 {
  strings:
    $key_7f04 = { 2b 6c [2] 5f 74 [2] 18 76 [2] 5f 67 [2] 11 6b [2] 1d 61 [2] 0a 6a [2] 11 24 [2] 2c }

  condition:
    any of them
}