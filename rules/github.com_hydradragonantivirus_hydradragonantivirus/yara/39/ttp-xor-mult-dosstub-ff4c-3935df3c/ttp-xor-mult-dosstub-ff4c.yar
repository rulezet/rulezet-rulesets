rule TTP_XOR_MULT_DOSStub_ff4c {
  strings:
    $key_ff4c = { ab 24 [2] df 3c [2] 98 3e [2] df 2f [2] 91 23 [2] 9d 29 [2] 8a 22 [2] 91 6c [2] ac }

  condition:
    any of them
}