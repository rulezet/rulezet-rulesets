rule TTP_XOR_MULT_DOSStub_3f2a {
  strings:
    $key_3f2a = { 6b 42 [2] 1f 5a [2] 58 58 [2] 1f 49 [2] 51 45 [2] 5d 4f [2] 4a 44 [2] 51 0a [2] 6c }

  condition:
    any of them
}