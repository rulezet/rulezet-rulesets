rule TTP_XOR_MULT_DOSStub_1f1d {
  strings:
    $key_1f1d = { 4b 75 [2] 3f 6d [2] 78 6f [2] 3f 7e [2] 71 72 [2] 7d 78 [2] 6a 73 [2] 71 3d [2] 4c }

  condition:
    any of them
}