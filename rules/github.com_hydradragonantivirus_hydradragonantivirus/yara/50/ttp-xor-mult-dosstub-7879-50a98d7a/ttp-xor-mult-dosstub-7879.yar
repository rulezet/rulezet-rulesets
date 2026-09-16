rule TTP_XOR_MULT_DOSStub_7879 {
  strings:
    $key_7879 = { 2c 11 [2] 58 09 [2] 1f 0b [2] 58 1a [2] 16 16 [2] 1a 1c [2] 0d 17 [2] 16 59 [2] 2b }

  condition:
    any of them
}