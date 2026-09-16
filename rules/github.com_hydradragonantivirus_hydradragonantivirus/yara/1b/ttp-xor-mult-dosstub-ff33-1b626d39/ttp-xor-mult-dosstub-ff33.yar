rule TTP_XOR_MULT_DOSStub_ff33 {
  strings:
    $key_ff33 = { ab 5b [2] df 43 [2] 98 41 [2] df 50 [2] 91 5c [2] 9d 56 [2] 8a 5d [2] 91 13 [2] ac }

  condition:
    any of them
}