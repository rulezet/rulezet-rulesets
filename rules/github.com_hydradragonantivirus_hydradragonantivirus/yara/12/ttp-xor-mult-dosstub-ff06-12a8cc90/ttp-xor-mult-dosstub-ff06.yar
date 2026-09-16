rule TTP_XOR_MULT_DOSStub_ff06 {
  strings:
    $key_ff06 = { ab 6e [2] df 76 [2] 98 74 [2] df 65 [2] 91 69 [2] 9d 63 [2] 8a 68 [2] 91 26 [2] ac }

  condition:
    any of them
}