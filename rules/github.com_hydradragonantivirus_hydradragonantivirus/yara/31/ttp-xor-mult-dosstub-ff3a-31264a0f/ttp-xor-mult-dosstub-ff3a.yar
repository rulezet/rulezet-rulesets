rule TTP_XOR_MULT_DOSStub_ff3a {
  strings:
    $key_ff3a = { ab 52 [2] df 4a [2] 98 48 [2] df 59 [2] 91 55 [2] 9d 5f [2] 8a 54 [2] 91 1a [2] ac }

  condition:
    any of them
}