rule TTP_XOR_MULT_DOSStub_261d {
  strings:
    $key_261d = { 72 75 [2] 06 6d [2] 41 6f [2] 06 7e [2] 48 72 [2] 44 78 [2] 53 73 [2] 48 3d [2] 75 }

  condition:
    any of them
}