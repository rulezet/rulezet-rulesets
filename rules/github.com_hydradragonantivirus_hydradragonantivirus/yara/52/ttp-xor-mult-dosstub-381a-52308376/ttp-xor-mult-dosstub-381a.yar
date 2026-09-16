rule TTP_XOR_MULT_DOSStub_381a {
  strings:
    $key_381a = { 6c 72 [2] 18 6a [2] 5f 68 [2] 18 79 [2] 56 75 [2] 5a 7f [2] 4d 74 [2] 56 3a [2] 6b }

  condition:
    any of them
}