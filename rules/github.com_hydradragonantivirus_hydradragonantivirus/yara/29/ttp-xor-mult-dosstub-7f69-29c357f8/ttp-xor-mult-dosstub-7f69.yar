rule TTP_XOR_MULT_DOSStub_7f69 {
  strings:
    $key_7f69 = { 2b 01 [2] 5f 19 [2] 18 1b [2] 5f 0a [2] 11 06 [2] 1d 0c [2] 0a 07 [2] 11 49 [2] 2c }

  condition:
    any of them
}