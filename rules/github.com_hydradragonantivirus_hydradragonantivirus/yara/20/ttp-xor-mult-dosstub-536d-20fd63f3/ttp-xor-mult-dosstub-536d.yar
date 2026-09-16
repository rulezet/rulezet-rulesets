rule TTP_XOR_MULT_DOSStub_536d {
  strings:
    $key_536d = { 07 05 [2] 73 1d [2] 34 1f [2] 73 0e [2] 3d 02 [2] 31 08 [2] 26 03 [2] 3d 4d [2] 00 }

  condition:
    any of them
}