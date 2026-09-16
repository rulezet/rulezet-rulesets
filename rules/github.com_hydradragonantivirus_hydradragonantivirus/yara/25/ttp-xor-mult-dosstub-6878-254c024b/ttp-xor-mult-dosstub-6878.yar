rule TTP_XOR_MULT_DOSStub_6878 {
  strings:
    $key_6878 = { 3c 10 [2] 48 08 [2] 0f 0a [2] 48 1b [2] 06 17 [2] 0a 1d [2] 1d 16 [2] 06 58 [2] 3b }

  condition:
    any of them
}