rule TTP_XOR_MULT_DOSStub_18fb {
  strings:
    $key_18fb = { 4c 93 [2] 38 8b [2] 7f 89 [2] 38 98 [2] 76 94 [2] 7a 9e [2] 6d 95 [2] 76 db [2] 4b }

  condition:
    any of them
}