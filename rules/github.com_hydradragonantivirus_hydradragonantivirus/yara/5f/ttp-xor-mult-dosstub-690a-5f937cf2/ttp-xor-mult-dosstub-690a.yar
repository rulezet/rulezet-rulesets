rule TTP_XOR_MULT_DOSStub_690a {
  strings:
    $key_690a = { 3d 62 [2] 49 7a [2] 0e 78 [2] 49 69 [2] 07 65 [2] 0b 6f [2] 1c 64 [2] 07 2a [2] 3a }

  condition:
    any of them
}