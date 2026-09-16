rule TTP_XOR_MULT_DOSStub_602a {
  strings:
    $key_602a = { 34 42 [2] 40 5a [2] 07 58 [2] 40 49 [2] 0e 45 [2] 02 4f [2] 15 44 [2] 0e 0a [2] 33 }

  condition:
    any of them
}