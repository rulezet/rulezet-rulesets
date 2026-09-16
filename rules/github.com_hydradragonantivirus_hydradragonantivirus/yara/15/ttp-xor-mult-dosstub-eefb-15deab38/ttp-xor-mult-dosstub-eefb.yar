rule TTP_XOR_MULT_DOSStub_eefb {
  strings:
    $key_eefb = { ba 93 [2] ce 8b [2] 89 89 [2] ce 98 [2] 80 94 [2] 8c 9e [2] 9b 95 [2] 80 db [2] bd }

  condition:
    any of them
}