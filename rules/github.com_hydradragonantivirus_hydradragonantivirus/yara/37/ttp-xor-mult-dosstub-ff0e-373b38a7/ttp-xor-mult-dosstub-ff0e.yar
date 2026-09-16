rule TTP_XOR_MULT_DOSStub_ff0e {
  strings:
    $key_ff0e = { ab 66 [2] df 7e [2] 98 7c [2] df 6d [2] 91 61 [2] 9d 6b [2] 8a 60 [2] 91 2e [2] ac }

  condition:
    any of them
}