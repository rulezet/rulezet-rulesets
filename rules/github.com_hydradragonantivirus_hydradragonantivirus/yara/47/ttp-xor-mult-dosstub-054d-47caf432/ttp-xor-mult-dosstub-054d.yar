rule TTP_XOR_MULT_DOSStub_054d {
  strings:
    $key_054d = { 51 25 [2] 25 3d [2] 62 3f [2] 25 2e [2] 6b 22 [2] 67 28 [2] 70 23 [2] 6b 6d [2] 56 }

  condition:
    any of them
}