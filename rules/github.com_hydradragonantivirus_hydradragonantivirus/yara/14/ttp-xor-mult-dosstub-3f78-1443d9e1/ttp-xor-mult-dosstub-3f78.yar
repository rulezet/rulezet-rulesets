rule TTP_XOR_MULT_DOSStub_3f78 {
  strings:
    $key_3f78 = { 6b 10 [2] 1f 08 [2] 58 0a [2] 1f 1b [2] 51 17 [2] 5d 1d [2] 4a 16 [2] 51 58 [2] 6c }

  condition:
    any of them
}