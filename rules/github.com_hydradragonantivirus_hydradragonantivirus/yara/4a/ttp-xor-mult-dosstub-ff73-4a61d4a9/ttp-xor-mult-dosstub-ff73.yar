rule TTP_XOR_MULT_DOSStub_ff73 {
  strings:
    $key_ff73 = { ab 1b [2] df 03 [2] 98 01 [2] df 10 [2] 91 1c [2] 9d 16 [2] 8a 1d [2] 91 53 [2] ac }

  condition:
    any of them
}