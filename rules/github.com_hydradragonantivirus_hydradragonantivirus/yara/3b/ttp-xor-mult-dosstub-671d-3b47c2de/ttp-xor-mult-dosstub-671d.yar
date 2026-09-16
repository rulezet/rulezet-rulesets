rule TTP_XOR_MULT_DOSStub_671d {
  strings:
    $key_671d = { 33 75 [2] 47 6d [2] 00 6f [2] 47 7e [2] 09 72 [2] 05 78 [2] 12 73 [2] 09 3d [2] 34 }

  condition:
    any of them
}