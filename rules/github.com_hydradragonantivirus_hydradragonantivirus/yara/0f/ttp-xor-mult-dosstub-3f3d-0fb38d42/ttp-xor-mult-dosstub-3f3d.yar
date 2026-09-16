rule TTP_XOR_MULT_DOSStub_3f3d {
  strings:
    $key_3f3d = { 6b 55 [2] 1f 4d [2] 58 4f [2] 1f 5e [2] 51 52 [2] 5d 58 [2] 4a 53 [2] 51 1d [2] 6c }

  condition:
    any of them
}