rule TTP_XOR_MULT_DOSStub_641d {
  strings:
    $key_641d = { 30 75 [2] 44 6d [2] 03 6f [2] 44 7e [2] 0a 72 [2] 06 78 [2] 11 73 [2] 0a 3d [2] 37 }

  condition:
    any of them
}