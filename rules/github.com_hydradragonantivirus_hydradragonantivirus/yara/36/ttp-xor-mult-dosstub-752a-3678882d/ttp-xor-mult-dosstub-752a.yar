rule TTP_XOR_MULT_DOSStub_752a {
  strings:
    $key_752a = { 21 42 [2] 55 5a [2] 12 58 [2] 55 49 [2] 1b 45 [2] 17 4f [2] 00 44 [2] 1b 0a [2] 26 }

  condition:
    any of them
}