rule TTP_XOR_MULT_DOSStub_6f3d {
  strings:
    $key_6f3d = { 3b 55 [2] 4f 4d [2] 08 4f [2] 4f 5e [2] 01 52 [2] 0d 58 [2] 1a 53 [2] 01 1d [2] 3c }

  condition:
    any of them
}