rule TTP_XOR_MULT_DOSStub_7839 {
  strings:
    $key_7839 = { 2c 51 [2] 58 49 [2] 1f 4b [2] 58 5a [2] 16 56 [2] 1a 5c [2] 0d 57 [2] 16 19 [2] 2b }

  condition:
    any of them
}