rule TTP_XOR_MULT_DOSStub_362a {
  strings:
    $key_362a = { 62 42 [2] 16 5a [2] 51 58 [2] 16 49 [2] 58 45 [2] 54 4f [2] 43 44 [2] 58 0a [2] 65 }

  condition:
    any of them
}