rule TTP_XOR_MULT_DOSStub_ff53 {
  strings:
    $key_ff53 = { ab 3b [2] df 23 [2] 98 21 [2] df 30 [2] 91 3c [2] 9d 36 [2] 8a 3d [2] 91 73 [2] ac }

  condition:
    any of them
}