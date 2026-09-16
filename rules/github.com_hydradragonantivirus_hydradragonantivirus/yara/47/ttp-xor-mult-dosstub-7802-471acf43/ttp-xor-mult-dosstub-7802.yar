rule TTP_XOR_MULT_DOSStub_7802 {
  strings:
    $key_7802 = { 2c 6a [2] 58 72 [2] 1f 70 [2] 58 61 [2] 16 6d [2] 1a 67 [2] 0d 6c [2] 16 22 [2] 2b }

  condition:
    any of them
}