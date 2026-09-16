rule TTP_XOR_MULT_DOSStub_694a {
  strings:
    $key_694a = { 3d 22 [2] 49 3a [2] 0e 38 [2] 49 29 [2] 07 25 [2] 0b 2f [2] 1c 24 [2] 07 6a [2] 3a }

  condition:
    any of them
}