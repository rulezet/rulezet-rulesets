rule TTP_XOR_MULT_DOSStub_4850 {
  strings:
    $key_4850 = { 1c 38 [2] 68 20 [2] 2f 22 [2] 68 33 [2] 26 3f [2] 2a 35 [2] 3d 3e [2] 26 70 [2] 1b }

  condition:
    any of them
}