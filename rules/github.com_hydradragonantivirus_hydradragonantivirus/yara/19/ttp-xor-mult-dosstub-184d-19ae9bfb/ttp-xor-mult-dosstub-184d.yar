rule TTP_XOR_MULT_DOSStub_184d {
  strings:
    $key_184d = { 4c 25 [2] 38 3d [2] 7f 3f [2] 38 2e [2] 76 22 [2] 7a 28 [2] 6d 23 [2] 76 6d [2] 4b }

  condition:
    any of them
}