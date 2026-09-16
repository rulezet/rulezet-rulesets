rule TTP_XOR_MULT_DOSStub_ff7e {
  strings:
    $key_ff7e = { ab 16 [2] df 0e [2] 98 0c [2] df 1d [2] 91 11 [2] 9d 1b [2] 8a 10 [2] 91 5e [2] ac }

  condition:
    any of them
}