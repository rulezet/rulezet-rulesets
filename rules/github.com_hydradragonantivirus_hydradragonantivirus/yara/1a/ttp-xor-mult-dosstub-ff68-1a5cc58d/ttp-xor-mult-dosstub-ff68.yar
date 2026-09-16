rule TTP_XOR_MULT_DOSStub_ff68 {
  strings:
    $key_ff68 = { ab 00 [2] df 18 [2] 98 1a [2] df 0b [2] 91 07 [2] 9d 0d [2] 8a 06 [2] 91 48 [2] ac }

  condition:
    any of them
}