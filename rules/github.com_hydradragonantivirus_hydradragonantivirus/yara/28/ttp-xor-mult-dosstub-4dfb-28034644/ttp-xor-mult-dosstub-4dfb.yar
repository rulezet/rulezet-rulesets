rule TTP_XOR_MULT_DOSStub_4dfb {
  strings:
    $key_4dfb = { 19 93 [2] 6d 8b [2] 2a 89 [2] 6d 98 [2] 23 94 [2] 2f 9e [2] 38 95 [2] 23 db [2] 1e }

  condition:
    any of them
}