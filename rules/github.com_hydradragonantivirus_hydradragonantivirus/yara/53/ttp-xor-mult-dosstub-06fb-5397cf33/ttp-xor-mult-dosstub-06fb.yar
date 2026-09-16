rule TTP_XOR_MULT_DOSStub_06fb {
  strings:
    $key_06fb = { 52 93 [2] 26 8b [2] 61 89 [2] 26 98 [2] 68 94 [2] 64 9e [2] 73 95 [2] 68 db [2] 55 }

  condition:
    any of them
}