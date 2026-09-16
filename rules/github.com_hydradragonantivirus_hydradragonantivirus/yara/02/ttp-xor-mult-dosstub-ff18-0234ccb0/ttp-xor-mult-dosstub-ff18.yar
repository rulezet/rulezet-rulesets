rule TTP_XOR_MULT_DOSStub_ff18 {
  strings:
    $key_ff18 = { ab 70 [2] df 68 [2] 98 6a [2] df 7b [2] 91 77 [2] 9d 7d [2] 8a 76 [2] 91 38 [2] ac }

  condition:
    any of them
}