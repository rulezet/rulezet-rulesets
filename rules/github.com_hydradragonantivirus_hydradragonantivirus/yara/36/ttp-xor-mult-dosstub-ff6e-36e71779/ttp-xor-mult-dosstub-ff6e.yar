rule TTP_XOR_MULT_DOSStub_ff6e {
  strings:
    $key_ff6e = { ab 06 [2] df 1e [2] 98 1c [2] df 0d [2] 91 01 [2] 9d 0b [2] 8a 00 [2] 91 4e [2] ac }

  condition:
    any of them
}