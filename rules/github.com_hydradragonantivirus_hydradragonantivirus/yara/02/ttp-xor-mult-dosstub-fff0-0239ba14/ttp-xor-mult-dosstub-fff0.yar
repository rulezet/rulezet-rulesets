rule TTP_XOR_MULT_DOSStub_fff0 {
  strings:
    $key_fff0 = { ab 98 [2] df 80 [2] 98 82 [2] df 93 [2] 91 9f [2] 9d 95 [2] 8a 9e [2] 91 d0 [2] ac }

  condition:
    any of them
}