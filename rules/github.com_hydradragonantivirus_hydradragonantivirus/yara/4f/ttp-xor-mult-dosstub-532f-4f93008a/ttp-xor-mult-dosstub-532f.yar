rule TTP_XOR_MULT_DOSStub_532f {
  strings:
    $key_532f = { 07 47 [2] 73 5f [2] 34 5d [2] 73 4c [2] 3d 40 [2] 31 4a [2] 26 41 [2] 3d 0f [2] 00 }

  condition:
    any of them
}