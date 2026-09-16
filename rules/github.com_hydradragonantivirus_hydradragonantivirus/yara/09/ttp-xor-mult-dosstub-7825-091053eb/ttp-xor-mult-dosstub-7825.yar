rule TTP_XOR_MULT_DOSStub_7825 {
  strings:
    $key_7825 = { 2c 4d [2] 58 55 [2] 1f 57 [2] 58 46 [2] 16 4a [2] 1a 40 [2] 0d 4b [2] 16 05 [2] 2b }

  condition:
    any of them
}