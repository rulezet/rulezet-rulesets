rule TTP_XOR_MULT_DOSStub_ff5e {
  strings:
    $key_ff5e = { ab 36 [2] df 2e [2] 98 2c [2] df 3d [2] 91 31 [2] 9d 3b [2] 8a 30 [2] 91 7e [2] ac }

  condition:
    any of them
}