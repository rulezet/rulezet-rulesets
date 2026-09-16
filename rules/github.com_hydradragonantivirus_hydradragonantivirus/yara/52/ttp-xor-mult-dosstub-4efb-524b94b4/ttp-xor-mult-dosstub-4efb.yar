rule TTP_XOR_MULT_DOSStub_4efb {
  strings:
    $key_4efb = { 1a 93 [2] 6e 8b [2] 29 89 [2] 6e 98 [2] 20 94 [2] 2c 9e [2] 3b 95 [2] 20 db [2] 1d }

  condition:
    any of them
}