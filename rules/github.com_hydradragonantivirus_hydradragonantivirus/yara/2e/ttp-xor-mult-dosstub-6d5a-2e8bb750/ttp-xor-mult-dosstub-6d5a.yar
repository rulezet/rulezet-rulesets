rule TTP_XOR_MULT_DOSStub_6d5a {
  strings:
    $key_6d5a = { 39 32 [2] 4d 2a [2] 0a 28 [2] 4d 39 [2] 03 35 [2] 0f 3f [2] 18 34 [2] 03 7a [2] 3e }

  condition:
    any of them
}