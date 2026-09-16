rule TTP_XOR_MULT_DOSStub_ff78 {
  strings:
    $key_ff78 = { ab 10 [2] df 08 [2] 98 0a [2] df 1b [2] 91 17 [2] 9d 1d [2] 8a 16 [2] 91 58 [2] ac }

  condition:
    any of them
}