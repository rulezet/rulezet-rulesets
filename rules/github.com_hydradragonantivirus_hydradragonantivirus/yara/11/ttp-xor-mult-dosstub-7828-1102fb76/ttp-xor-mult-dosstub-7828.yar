rule TTP_XOR_MULT_DOSStub_7828 {
  strings:
    $key_7828 = { 2c 40 [2] 58 58 [2] 1f 5a [2] 58 4b [2] 16 47 [2] 1a 4d [2] 0d 46 [2] 16 08 [2] 2b }

  condition:
    any of them
}