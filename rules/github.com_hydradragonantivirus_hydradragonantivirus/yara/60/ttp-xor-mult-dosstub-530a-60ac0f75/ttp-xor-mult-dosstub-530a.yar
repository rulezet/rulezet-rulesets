rule TTP_XOR_MULT_DOSStub_530a {
  strings:
    $key_530a = { 07 62 [2] 73 7a [2] 34 78 [2] 73 69 [2] 3d 65 [2] 31 6f [2] 26 64 [2] 3d 2a [2] 00 }

  condition:
    any of them
}