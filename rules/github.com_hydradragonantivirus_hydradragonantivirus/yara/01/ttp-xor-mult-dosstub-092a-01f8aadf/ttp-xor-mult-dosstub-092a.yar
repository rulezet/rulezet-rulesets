rule TTP_XOR_MULT_DOSStub_092a {
  strings:
    $key_092a = { 5d 42 [2] 29 5a [2] 6e 58 [2] 29 49 [2] 67 45 [2] 6b 4f [2] 7c 44 [2] 67 0a [2] 5a }

  condition:
    any of them
}