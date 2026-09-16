rule TTP_XOR_MULT_DOSStub_39fb {
  strings:
    $key_39fb = { 6d 93 [2] 19 8b [2] 5e 89 [2] 19 98 [2] 57 94 [2] 5b 9e [2] 4c 95 [2] 57 db [2] 6a }

  condition:
    any of them
}