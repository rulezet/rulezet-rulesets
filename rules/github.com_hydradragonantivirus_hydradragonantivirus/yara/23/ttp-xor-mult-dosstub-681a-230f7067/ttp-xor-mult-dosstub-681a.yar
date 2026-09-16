rule TTP_XOR_MULT_DOSStub_681a {
  strings:
    $key_681a = { 3c 72 [2] 48 6a [2] 0f 68 [2] 48 79 [2] 06 75 [2] 0a 7f [2] 1d 74 [2] 06 3a [2] 3b }

  condition:
    any of them
}