rule TTP_XOR_MULT_DOSStub_684a {
  strings:
    $key_684a = { 3c 22 [2] 48 3a [2] 0f 38 [2] 48 29 [2] 06 25 [2] 0a 2f [2] 1d 24 [2] 06 6a [2] 3b }

  condition:
    any of them
}