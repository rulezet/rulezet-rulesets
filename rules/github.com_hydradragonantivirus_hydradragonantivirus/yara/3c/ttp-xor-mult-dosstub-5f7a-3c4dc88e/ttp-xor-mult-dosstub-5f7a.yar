rule TTP_XOR_MULT_DOSStub_5f7a {
  strings:
    $key_5f7a = { 0b 12 [2] 7f 0a [2] 38 08 [2] 7f 19 [2] 31 15 [2] 3d 1f [2] 2a 14 [2] 31 5a [2] 0c }

  condition:
    any of them
}