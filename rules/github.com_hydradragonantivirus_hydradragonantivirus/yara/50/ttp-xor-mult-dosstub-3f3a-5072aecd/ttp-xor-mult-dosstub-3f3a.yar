rule TTP_XOR_MULT_DOSStub_3f3a {
  strings:
    $key_3f3a = { 6b 52 [2] 1f 4a [2] 58 48 [2] 1f 59 [2] 51 55 [2] 5d 5f [2] 4a 54 [2] 51 1a [2] 6c }

  condition:
    any of them
}