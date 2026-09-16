rule TTP_XOR_MULT_DOSStub_5f3a {
  strings:
    $key_5f3a = { 0b 52 [2] 7f 4a [2] 38 48 [2] 7f 59 [2] 31 55 [2] 3d 5f [2] 2a 54 [2] 31 1a [2] 0c }

  condition:
    any of them
}