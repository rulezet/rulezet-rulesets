rule TTP_XOR_MULT_DOSStub_ff6a {
  strings:
    $key_ff6a = { ab 02 [2] df 1a [2] 98 18 [2] df 09 [2] 91 05 [2] 9d 0f [2] 8a 04 [2] 91 4a [2] ac }

  condition:
    any of them
}