rule TTP_XOR_MULT_DOSStub_0f78 {
  strings:
    $key_0f78 = { 5b 10 [2] 2f 08 [2] 68 0a [2] 2f 1b [2] 61 17 [2] 6d 1d [2] 7a 16 [2] 61 58 [2] 5c }

  condition:
    any of them
}