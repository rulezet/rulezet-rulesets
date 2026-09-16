rule TTP_XOR_MULT_DOSStub_29fb {
  strings:
    $key_29fb = { 7d 93 [2] 09 8b [2] 4e 89 [2] 09 98 [2] 47 94 [2] 4b 9e [2] 5c 95 [2] 47 db [2] 7a }

  condition:
    any of them
}