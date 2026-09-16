rule TTP_XOR_MULT_DOSStub_ecfb {
  strings:
    $key_ecfb = { b8 93 [2] cc 8b [2] 8b 89 [2] cc 98 [2] 82 94 [2] 8e 9e [2] 99 95 [2] 82 db [2] bf }

  condition:
    any of them
}