rule TTP_XOR_MULT_DOSStub_ff64 {
  strings:
    $key_ff64 = { ab 0c [2] df 14 [2] 98 16 [2] df 07 [2] 91 0b [2] 9d 01 [2] 8a 0a [2] 91 44 [2] ac }

  condition:
    any of them
}