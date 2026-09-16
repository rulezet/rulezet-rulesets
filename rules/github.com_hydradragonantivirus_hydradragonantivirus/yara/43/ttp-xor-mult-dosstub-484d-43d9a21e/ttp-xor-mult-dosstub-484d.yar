rule TTP_XOR_MULT_DOSStub_484d {
  strings:
    $key_484d = { 1c 25 [2] 68 3d [2] 2f 3f [2] 68 2e [2] 26 22 [2] 2a 28 [2] 3d 23 [2] 26 6d [2] 1b }

  condition:
    any of them
}