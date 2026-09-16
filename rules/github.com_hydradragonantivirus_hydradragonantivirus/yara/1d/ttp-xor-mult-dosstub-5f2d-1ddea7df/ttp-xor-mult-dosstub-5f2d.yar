rule TTP_XOR_MULT_DOSStub_5f2d {
  strings:
    $key_5f2d = { 0b 45 [2] 7f 5d [2] 38 5f [2] 7f 4e [2] 31 42 [2] 3d 48 [2] 2a 43 [2] 31 0d [2] 0c }

  condition:
    any of them
}