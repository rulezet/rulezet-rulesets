rule TTP_XOR_MULT_DOSStub_331d {
  strings:
    $key_331d = { 67 75 [2] 13 6d [2] 54 6f [2] 13 7e [2] 5d 72 [2] 51 78 [2] 46 73 [2] 5d 3d [2] 60 }

  condition:
    any of them
}