rule TTP_XOR_MULT_DOSStub_2f1d {
  strings:
    $key_2f1d = { 7b 75 [2] 0f 6d [2] 48 6f [2] 0f 7e [2] 41 72 [2] 4d 78 [2] 5a 73 [2] 41 3d [2] 7c }

  condition:
    any of them
}