rule TTP_XOR_MULT_DOSStub_ff2b {
  strings:
    $key_ff2b = { ab 43 [2] df 5b [2] 98 59 [2] df 48 [2] 91 44 [2] 9d 4e [2] 8a 45 [2] 91 0b [2] ac }

  condition:
    any of them
}