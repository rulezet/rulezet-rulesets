rule TTP_XOR_MULT_DOSStub_762a {
  strings:
    $key_762a = { 22 42 [2] 56 5a [2] 11 58 [2] 56 49 [2] 18 45 [2] 14 4f [2] 03 44 [2] 18 0a [2] 25 }

  condition:
    any of them
}