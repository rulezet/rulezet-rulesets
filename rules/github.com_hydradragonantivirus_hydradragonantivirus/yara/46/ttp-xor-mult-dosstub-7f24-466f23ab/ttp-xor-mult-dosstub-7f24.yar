rule TTP_XOR_MULT_DOSStub_7f24 {
  strings:
    $key_7f24 = { 2b 4c [2] 5f 54 [2] 18 56 [2] 5f 47 [2] 11 4b [2] 1d 41 [2] 0a 4a [2] 11 04 [2] 2c }

  condition:
    any of them
}