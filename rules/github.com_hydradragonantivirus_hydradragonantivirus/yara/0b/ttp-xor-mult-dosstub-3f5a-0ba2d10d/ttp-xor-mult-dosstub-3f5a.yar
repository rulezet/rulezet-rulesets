rule TTP_XOR_MULT_DOSStub_3f5a {
  strings:
    $key_3f5a = { 6b 32 [2] 1f 2a [2] 58 28 [2] 1f 39 [2] 51 35 [2] 5d 3f [2] 4a 34 [2] 51 7a [2] 6c }

  condition:
    any of them
}