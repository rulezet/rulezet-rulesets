rule TTP_XOR_MULT_DOSStub_ff5d {
  strings:
    $key_ff5d = { ab 35 [2] df 2d [2] 98 2f [2] df 3e [2] 91 32 [2] 9d 38 [2] 8a 33 [2] 91 7d [2] ac }

  condition:
    any of them
}