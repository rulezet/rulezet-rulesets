rule TTP_XOR_MULT_DOSStub_697a {
  strings:
    $key_697a = { 3d 12 [2] 49 0a [2] 0e 08 [2] 49 19 [2] 07 15 [2] 0b 1f [2] 1c 14 [2] 07 5a [2] 3a }

  condition:
    any of them
}