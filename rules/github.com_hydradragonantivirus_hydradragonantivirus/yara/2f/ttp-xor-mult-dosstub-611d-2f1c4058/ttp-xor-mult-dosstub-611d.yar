rule TTP_XOR_MULT_DOSStub_611d {
  strings:
    $key_611d = { 35 75 [2] 41 6d [2] 06 6f [2] 41 7e [2] 0f 72 [2] 03 78 [2] 14 73 [2] 0f 3d [2] 32 }

  condition:
    any of them
}