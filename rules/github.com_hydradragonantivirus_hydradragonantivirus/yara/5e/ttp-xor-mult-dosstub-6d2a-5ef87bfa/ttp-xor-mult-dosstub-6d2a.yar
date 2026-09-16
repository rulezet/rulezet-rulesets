rule TTP_XOR_MULT_DOSStub_6d2a {
  strings:
    $key_6d2a = { 39 42 [2] 4d 5a [2] 0a 58 [2] 4d 49 [2] 03 45 [2] 0f 4f [2] 18 44 [2] 03 0a [2] 3e }

  condition:
    any of them
}