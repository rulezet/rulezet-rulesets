rule TTP_XOR_MULT_DOSStub_58fb {
  strings:
    $key_58fb = { 0c 93 [2] 78 8b [2] 3f 89 [2] 78 98 [2] 36 94 [2] 3a 9e [2] 2d 95 [2] 36 db [2] 0b }

  condition:
    any of them
}