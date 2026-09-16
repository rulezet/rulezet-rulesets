rule TTP_XOR_MULT_DOSStub_0f2a {
  strings:
    $key_0f2a = { 5b 42 [2] 2f 5a [2] 68 58 [2] 2f 49 [2] 61 45 [2] 6d 4f [2] 7a 44 [2] 61 0a [2] 5c }

  condition:
    any of them
}