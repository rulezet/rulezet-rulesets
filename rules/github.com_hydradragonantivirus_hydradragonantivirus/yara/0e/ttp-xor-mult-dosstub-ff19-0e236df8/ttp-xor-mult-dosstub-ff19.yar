rule TTP_XOR_MULT_DOSStub_ff19 {
  strings:
    $key_ff19 = { ab 71 [2] df 69 [2] 98 6b [2] df 7a [2] 91 76 [2] 9d 7c [2] 8a 77 [2] 91 39 [2] ac }

  condition:
    any of them
}