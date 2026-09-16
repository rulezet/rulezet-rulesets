rule TTP_XOR_MULT_DOSStub_2f2a {
  strings:
    $key_2f2a = { 7b 42 [2] 0f 5a [2] 48 58 [2] 0f 49 [2] 41 45 [2] 4d 4f [2] 5a 44 [2] 41 0a [2] 7c }

  condition:
    any of them
}