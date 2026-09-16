rule TTP_XOR_MULT_DOSStub_182a {
  strings:
    $key_182a = { 4c 42 [2] 38 5a [2] 7f 58 [2] 38 49 [2] 76 45 [2] 7a 4f [2] 6d 44 [2] 76 0a [2] 4b }

  condition:
    any of them
}