rule TTP_XOR_MULT_DOSStub_1f2a {
  strings:
    $key_1f2a = { 4b 42 [2] 3f 5a [2] 78 58 [2] 3f 49 [2] 71 45 [2] 7d 4f [2] 6a 44 [2] 71 0a [2] 4c }

  condition:
    any of them
}