rule TTP_XOR_MULT_DOSStub_ff66 {
  strings:
    $key_ff66 = { ab 0e [2] df 16 [2] 98 14 [2] df 05 [2] 91 09 [2] 9d 03 [2] 8a 08 [2] 91 46 [2] ac }

  condition:
    any of them
}