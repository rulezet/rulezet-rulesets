rule TTP_XOR_MULT_DOSStub_5f4d {
  strings:
    $key_5f4d = { 0b 25 [2] 7f 3d [2] 38 3f [2] 7f 2e [2] 31 22 [2] 3d 28 [2] 2a 23 [2] 31 6d [2] 0c }

  condition:
    any of them
}