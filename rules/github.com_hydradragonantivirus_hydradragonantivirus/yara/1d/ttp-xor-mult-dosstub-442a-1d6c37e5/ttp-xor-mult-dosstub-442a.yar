rule TTP_XOR_MULT_DOSStub_442a {
  strings:
    $key_442a = { 10 42 [2] 64 5a [2] 23 58 [2] 64 49 [2] 2a 45 [2] 26 4f [2] 31 44 [2] 2a 0a [2] 17 }

  condition:
    any of them
}