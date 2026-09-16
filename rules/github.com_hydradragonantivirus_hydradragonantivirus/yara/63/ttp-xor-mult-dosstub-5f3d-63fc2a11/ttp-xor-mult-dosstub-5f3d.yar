rule TTP_XOR_MULT_DOSStub_5f3d {
  strings:
    $key_5f3d = { 0b 55 [2] 7f 4d [2] 38 4f [2] 7f 5e [2] 31 52 [2] 3d 58 [2] 2a 53 [2] 31 1d [2] 0c }

  condition:
    any of them
}