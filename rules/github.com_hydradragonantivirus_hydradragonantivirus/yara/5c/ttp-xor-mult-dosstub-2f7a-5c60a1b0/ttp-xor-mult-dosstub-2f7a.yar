rule TTP_XOR_MULT_DOSStub_2f7a {
  strings:
    $key_2f7a = { 7b 12 [2] 0f 0a [2] 48 08 [2] 0f 19 [2] 41 15 [2] 4d 1f [2] 5a 14 [2] 41 5a [2] 7c }

  condition:
    any of them
}