rule TTP_XOR_MULT_DOSStub_ff36 {
  strings:
    $key_ff36 = { ab 5e [2] df 46 [2] 98 44 [2] df 55 [2] 91 59 [2] 9d 53 [2] 8a 58 [2] 91 16 [2] ac }

  condition:
    any of them
}