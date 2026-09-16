rule TTP_XOR_MULT_DOSStub_1f49 {
  strings:
    $key_1f49 = { 4b 21 [2] 3f 39 [2] 78 3b [2] 3f 2a [2] 71 26 [2] 7d 2c [2] 6a 27 [2] 71 69 [2] 4c }

  condition:
    any of them
}