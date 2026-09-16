rule TTP_XOR_MULT_DOSStub_fffb {
  strings:
    $key_fffb = { ab 93 [2] df 8b [2] 98 89 [2] df 98 [2] 91 94 [2] 9d 9e [2] 8a 95 [2] 91 db [2] ac }

  condition:
    any of them
}