rule TTP_XOR_MULT_DOSStub_134d {
  strings:
    $key_134d = { 47 25 [2] 33 3d [2] 74 3f [2] 33 2e [2] 7d 22 [2] 71 28 [2] 66 23 [2] 7d 6d [2] 40 }

  condition:
    any of them
}