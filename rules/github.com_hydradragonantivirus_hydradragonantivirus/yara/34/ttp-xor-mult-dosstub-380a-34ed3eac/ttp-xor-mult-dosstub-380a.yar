rule TTP_XOR_MULT_DOSStub_380a {
  strings:
    $key_380a = { 6c 62 [2] 18 7a [2] 5f 78 [2] 18 69 [2] 56 65 [2] 5a 6f [2] 4d 64 [2] 56 2a [2] 6b }

  condition:
    any of them
}