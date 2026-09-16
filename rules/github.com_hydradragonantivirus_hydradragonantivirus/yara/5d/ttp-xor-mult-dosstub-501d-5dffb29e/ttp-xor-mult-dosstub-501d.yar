rule TTP_XOR_MULT_DOSStub_501d {
  strings:
    $key_501d = { 04 75 [2] 70 6d [2] 37 6f [2] 70 7e [2] 3e 72 [2] 32 78 [2] 25 73 [2] 3e 3d [2] 03 }

  condition:
    any of them
}