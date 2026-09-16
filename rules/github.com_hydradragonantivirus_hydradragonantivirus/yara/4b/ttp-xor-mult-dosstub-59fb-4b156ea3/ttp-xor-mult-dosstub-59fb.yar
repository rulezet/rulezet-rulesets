rule TTP_XOR_MULT_DOSStub_59fb {
  strings:
    $key_59fb = { 0d 93 [2] 79 8b [2] 3e 89 [2] 79 98 [2] 37 94 [2] 3b 9e [2] 2c 95 [2] 37 db [2] 0a }

  condition:
    any of them
}