rule TTP_XOR_MULT_DOSStub_ff63 {
  strings:
    $key_ff63 = { ab 0b [2] df 13 [2] 98 11 [2] df 00 [2] 91 0c [2] 9d 06 [2] 8a 0d [2] 91 43 [2] ac }

  condition:
    any of them
}