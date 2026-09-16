rule TTP_XOR_MULT_DOSStub_69fb {
  strings:
    $key_69fb = { 3d 93 [2] 49 8b [2] 0e 89 [2] 49 98 [2] 07 94 [2] 0b 9e [2] 1c 95 [2] 07 db [2] 3a }

  condition:
    any of them
}