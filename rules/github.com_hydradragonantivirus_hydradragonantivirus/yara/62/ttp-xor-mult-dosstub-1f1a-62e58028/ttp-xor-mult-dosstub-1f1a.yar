rule TTP_XOR_MULT_DOSStub_1f1a {
  strings:
    $key_1f1a = { 4b 72 [2] 3f 6a [2] 78 68 [2] 3f 79 [2] 71 75 [2] 7d 7f [2] 6a 74 [2] 71 3a [2] 4c }

  condition:
    any of them
}