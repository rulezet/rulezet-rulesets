rule TTP_XOR_MULT_DOSStub_ff70 {
  strings:
    $key_ff70 = { ab 18 [2] df 00 [2] 98 02 [2] df 13 [2] 91 1f [2] 9d 15 [2] 8a 1e [2] 91 50 [2] ac }

  condition:
    any of them
}