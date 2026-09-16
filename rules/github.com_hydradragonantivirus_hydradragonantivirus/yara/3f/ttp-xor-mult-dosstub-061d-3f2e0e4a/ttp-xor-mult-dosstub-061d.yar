rule TTP_XOR_MULT_DOSStub_061d {
  strings:
    $key_061d = { 52 75 [2] 26 6d [2] 61 6f [2] 26 7e [2] 68 72 [2] 64 78 [2] 73 73 [2] 68 3d [2] 55 }

  condition:
    any of them
}