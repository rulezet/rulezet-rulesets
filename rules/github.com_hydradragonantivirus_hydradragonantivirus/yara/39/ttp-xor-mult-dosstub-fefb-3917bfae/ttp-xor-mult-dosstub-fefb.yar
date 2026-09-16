rule TTP_XOR_MULT_DOSStub_fefb {
  strings:
    $key_fefb = { aa 93 [2] de 8b [2] 99 89 [2] de 98 [2] 90 94 [2] 9c 9e [2] 8b 95 [2] 90 db [2] ad }

  condition:
    any of them
}