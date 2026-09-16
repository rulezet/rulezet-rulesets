rule TTP_XOR_MULT_DOSStub_ff2a {
  strings:
    $key_ff2a = { ab 42 [2] df 5a [2] 98 58 [2] df 49 [2] 91 45 [2] 9d 4f [2] 8a 44 [2] 91 0a [2] ac }

  condition:
    any of them
}