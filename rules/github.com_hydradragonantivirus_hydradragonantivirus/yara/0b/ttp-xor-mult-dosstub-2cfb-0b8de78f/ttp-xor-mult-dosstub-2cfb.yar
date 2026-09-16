rule TTP_XOR_MULT_DOSStub_2cfb {
  strings:
    $key_2cfb = { 78 93 [2] 0c 8b [2] 4b 89 [2] 0c 98 [2] 42 94 [2] 4e 9e [2] 59 95 [2] 42 db [2] 7f }

  condition:
    any of them
}