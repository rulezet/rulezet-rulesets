rule TTP_XOR_MULT_DOSStub_7813 {
  strings:
    $key_7813 = { 2c 7b [2] 58 63 [2] 1f 61 [2] 58 70 [2] 16 7c [2] 1a 76 [2] 0d 7d [2] 16 33 [2] 2b }

  condition:
    any of them
}