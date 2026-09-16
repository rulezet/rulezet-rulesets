rule TTP_XOR_MULT_DOSStub_ff77 {
  strings:
    $key_ff77 = { ab 1f [2] df 07 [2] 98 05 [2] df 14 [2] 91 18 [2] 9d 12 [2] 8a 19 [2] 91 57 [2] ac }

  condition:
    any of them
}