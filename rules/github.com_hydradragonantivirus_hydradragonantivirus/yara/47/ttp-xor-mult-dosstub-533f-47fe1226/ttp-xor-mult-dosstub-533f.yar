rule TTP_XOR_MULT_DOSStub_533f {
  strings:
    $key_533f = { 07 57 [2] 73 4f [2] 34 4d [2] 73 5c [2] 3d 50 [2] 31 5a [2] 26 51 [2] 3d 1f [2] 00 }

  condition:
    any of them
}