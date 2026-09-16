rule TTP_XOR_MULT_DOSStub_3f4d {
  strings:
    $key_3f4d = { 6b 25 [2] 1f 3d [2] 58 3f [2] 1f 2e [2] 51 22 [2] 5d 28 [2] 4a 23 [2] 51 6d [2] 6c }

  condition:
    any of them
}