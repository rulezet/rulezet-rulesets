rule TTP_XOR_MULT_DOSStub_530f {
  strings:
    $key_530f = { 07 67 [2] 73 7f [2] 34 7d [2] 73 6c [2] 3d 60 [2] 31 6a [2] 26 61 [2] 3d 2f [2] 00 }

  condition:
    any of them
}