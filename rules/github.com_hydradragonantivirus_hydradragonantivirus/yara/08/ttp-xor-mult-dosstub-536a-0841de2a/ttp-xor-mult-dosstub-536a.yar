rule TTP_XOR_MULT_DOSStub_536a {
  strings:
    $key_536a = { 07 02 [2] 73 1a [2] 34 18 [2] 73 09 [2] 3d 05 [2] 31 0f [2] 26 04 [2] 3d 4a [2] 00 }

  condition:
    any of them
}