rule TTP_XOR_MULT_DOSStub_5ffb {
  strings:
    $key_5ffb = { 0b 93 [2] 7f 8b [2] 38 89 [2] 7f 98 [2] 31 94 [2] 3d 9e [2] 2a 95 [2] 31 db [2] 0c }

  condition:
    any of them
}