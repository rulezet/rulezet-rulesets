rule TTP_XOR_MULT_DOSStub_7844 {
  strings:
    $key_7844 = { 2c 2c [2] 58 34 [2] 1f 36 [2] 58 27 [2] 16 2b [2] 1a 21 [2] 0d 2a [2] 16 64 [2] 2b }

  condition:
    any of them
}