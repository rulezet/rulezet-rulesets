rule TTP_XOR_MULT_DOSStub_1f4d {
  strings:
    $key_1f4d = { 4b 25 [2] 3f 3d [2] 78 3f [2] 3f 2e [2] 71 22 [2] 7d 28 [2] 6a 23 [2] 71 6d [2] 4c }

  condition:
    any of them
}