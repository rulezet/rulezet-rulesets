rule TTP_XOR_MULT_DOSStub_0dfb {
  strings:
    $key_0dfb = { 59 93 [2] 2d 8b [2] 6a 89 [2] 2d 98 [2] 63 94 [2] 6f 9e [2] 78 95 [2] 63 db [2] 5e }

  condition:
    any of them
}