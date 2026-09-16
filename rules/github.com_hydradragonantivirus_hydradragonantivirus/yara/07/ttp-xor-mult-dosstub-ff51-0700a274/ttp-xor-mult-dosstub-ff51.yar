rule TTP_XOR_MULT_DOSStub_ff51 {
  strings:
    $key_ff51 = { ab 39 [2] df 21 [2] 98 23 [2] df 32 [2] 91 3e [2] 9d 34 [2] 8a 3f [2] 91 71 [2] ac }

  condition:
    any of them
}