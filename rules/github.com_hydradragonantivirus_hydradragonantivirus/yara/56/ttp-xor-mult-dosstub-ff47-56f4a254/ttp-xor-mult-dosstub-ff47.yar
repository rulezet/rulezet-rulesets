rule TTP_XOR_MULT_DOSStub_ff47 {
  strings:
    $key_ff47 = { ab 2f [2] df 37 [2] 98 35 [2] df 24 [2] 91 28 [2] 9d 22 [2] 8a 29 [2] 91 67 [2] ac }

  condition:
    any of them
}