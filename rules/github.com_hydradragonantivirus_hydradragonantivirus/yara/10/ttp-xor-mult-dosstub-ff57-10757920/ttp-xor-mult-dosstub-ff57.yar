rule TTP_XOR_MULT_DOSStub_ff57 {
  strings:
    $key_ff57 = { ab 3f [2] df 27 [2] 98 25 [2] df 34 [2] 91 38 [2] 9d 32 [2] 8a 39 [2] 91 77 [2] ac }

  condition:
    any of them
}