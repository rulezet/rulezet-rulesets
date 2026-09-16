rule TTP_XOR_MULT_DOSStub_1cfb {
  strings:
    $key_1cfb = { 48 93 [2] 3c 8b [2] 7b 89 [2] 3c 98 [2] 72 94 [2] 7e 9e [2] 69 95 [2] 72 db [2] 4f }

  condition:
    any of them
}