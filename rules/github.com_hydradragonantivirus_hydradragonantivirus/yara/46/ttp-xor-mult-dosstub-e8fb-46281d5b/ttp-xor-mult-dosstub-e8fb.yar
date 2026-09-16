rule TTP_XOR_MULT_DOSStub_e8fb {
  strings:
    $key_e8fb = { bc 93 [2] c8 8b [2] 8f 89 [2] c8 98 [2] 86 94 [2] 8a 9e [2] 9d 95 [2] 86 db [2] bb }

  condition:
    any of them
}