rule TTP_XOR_MULT_DOSStub_3f75 {
  strings:
    $key_3f75 = { 6b 1d [2] 1f 05 [2] 58 07 [2] 1f 16 [2] 51 1a [2] 5d 10 [2] 4a 1b [2] 51 55 [2] 6c }

  condition:
    any of them
}