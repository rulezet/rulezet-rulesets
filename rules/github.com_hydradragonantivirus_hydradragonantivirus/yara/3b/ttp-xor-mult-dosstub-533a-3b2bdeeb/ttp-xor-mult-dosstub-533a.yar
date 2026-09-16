rule TTP_XOR_MULT_DOSStub_533a {
  strings:
    $key_533a = { 07 52 [2] 73 4a [2] 34 48 [2] 73 59 [2] 3d 55 [2] 31 5f [2] 26 54 [2] 3d 1a [2] 00 }

  condition:
    any of them
}