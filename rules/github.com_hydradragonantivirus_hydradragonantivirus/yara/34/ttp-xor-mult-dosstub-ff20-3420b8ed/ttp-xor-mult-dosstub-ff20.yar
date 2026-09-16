rule TTP_XOR_MULT_DOSStub_ff20 {
  strings:
    $key_ff20 = { ab 48 [2] df 50 [2] 98 52 [2] df 43 [2] 91 4f [2] 9d 45 [2] 8a 4e [2] 91 00 [2] ac }

  condition:
    any of them
}