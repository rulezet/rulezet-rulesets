rule TTP_XOR_MULT_DOSStub_141d {
  strings:
    $key_141d = { 40 75 [2] 34 6d [2] 73 6f [2] 34 7e [2] 7a 72 [2] 76 78 [2] 61 73 [2] 7a 3d [2] 47 }

  condition:
    any of them
}