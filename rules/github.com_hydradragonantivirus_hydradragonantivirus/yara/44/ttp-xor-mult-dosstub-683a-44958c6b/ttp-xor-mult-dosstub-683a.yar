rule TTP_XOR_MULT_DOSStub_683a {
  strings:
    $key_683a = { 3c 52 [2] 48 4a [2] 0f 48 [2] 48 59 [2] 06 55 [2] 0a 5f [2] 1d 54 [2] 06 1a [2] 3b }

  condition:
    any of them
}