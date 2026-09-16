rule TTP_XOR_MULT_DOSStub_ff69 {
  strings:
    $key_ff69 = { ab 01 [2] df 19 [2] 98 1b [2] df 0a [2] 91 06 [2] 9d 0c [2] 8a 07 [2] 91 49 [2] ac }

  condition:
    any of them
}