rule TTP_XOR_MULT_DOSStub_ff21 {
  strings:
    $key_ff21 = { ab 49 [2] df 51 [2] 98 53 [2] df 42 [2] 91 4e [2] 9d 44 [2] 8a 4f [2] 91 01 [2] ac }

  condition:
    any of them
}