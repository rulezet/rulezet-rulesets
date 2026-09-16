rule TTP_XOR_MULT_DOSStub_6a4d {
  strings:
    $key_6a4d = { 3e 25 [2] 4a 3d [2] 0d 3f [2] 4a 2e [2] 04 22 [2] 08 28 [2] 1f 23 [2] 04 6d [2] 39 }

  condition:
    any of them
}