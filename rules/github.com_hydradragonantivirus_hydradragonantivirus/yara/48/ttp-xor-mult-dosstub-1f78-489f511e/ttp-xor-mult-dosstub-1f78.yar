rule TTP_XOR_MULT_DOSStub_1f78 {
  strings:
    $key_1f78 = { 4b 10 [2] 3f 08 [2] 78 0a [2] 3f 1b [2] 71 17 [2] 7d 1d [2] 6a 16 [2] 71 58 [2] 4c }

  condition:
    any of them
}