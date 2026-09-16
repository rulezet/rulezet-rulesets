rule TTP_XOR_MULT_DOSStub_ff00 {
  strings:
    $key_ff00 = { ab 68 [2] df 70 [2] 98 72 [2] df 63 [2] 91 6f [2] 9d 65 [2] 8a 6e [2] 91 20 [2] ac }

  condition:
    any of them
}