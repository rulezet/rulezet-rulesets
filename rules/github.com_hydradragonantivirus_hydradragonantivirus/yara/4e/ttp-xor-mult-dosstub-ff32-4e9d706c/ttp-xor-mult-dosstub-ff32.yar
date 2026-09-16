rule TTP_XOR_MULT_DOSStub_ff32 {
  strings:
    $key_ff32 = { ab 5a [2] df 42 [2] 98 40 [2] df 51 [2] 91 5d [2] 9d 57 [2] 8a 5c [2] 91 12 [2] ac }

  condition:
    any of them
}