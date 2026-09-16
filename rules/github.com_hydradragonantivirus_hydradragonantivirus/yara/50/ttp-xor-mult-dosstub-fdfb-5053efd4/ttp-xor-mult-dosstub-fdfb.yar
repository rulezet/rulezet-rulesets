rule TTP_XOR_MULT_DOSStub_fdfb {
  strings:
    $key_fdfb = { a9 93 [2] dd 8b [2] 9a 89 [2] dd 98 [2] 93 94 [2] 9f 9e [2] 88 95 [2] 93 db [2] ae }

  condition:
    any of them
}