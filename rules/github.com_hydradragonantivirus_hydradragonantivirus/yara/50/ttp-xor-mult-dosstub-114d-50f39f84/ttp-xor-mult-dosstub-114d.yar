rule TTP_XOR_MULT_DOSStub_114d {
  strings:
    $key_114d = { 45 25 [2] 31 3d [2] 76 3f [2] 31 2e [2] 7f 22 [2] 73 28 [2] 64 23 [2] 7f 6d [2] 42 }

  condition:
    any of them
}