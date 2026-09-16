rule TTP_XOR_MULT_DOSStub_28fb {
  strings:
    $key_28fb = { 7c 93 [2] 08 8b [2] 4f 89 [2] 08 98 [2] 46 94 [2] 4a 9e [2] 5d 95 [2] 46 db [2] 7b }

  condition:
    any of them
}