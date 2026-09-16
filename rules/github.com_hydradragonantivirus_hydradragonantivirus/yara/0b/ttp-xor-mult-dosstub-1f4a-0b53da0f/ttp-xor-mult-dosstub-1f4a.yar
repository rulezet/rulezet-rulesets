rule TTP_XOR_MULT_DOSStub_1f4a {
  strings:
    $key_1f4a = { 4b 22 [2] 3f 3a [2] 78 38 [2] 3f 29 [2] 71 25 [2] 7d 2f [2] 6a 24 [2] 71 6a [2] 4c }

  condition:
    any of them
}