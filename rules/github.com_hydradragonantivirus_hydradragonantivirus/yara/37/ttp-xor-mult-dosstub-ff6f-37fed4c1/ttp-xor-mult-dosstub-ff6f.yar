rule TTP_XOR_MULT_DOSStub_ff6f {
  strings:
    $key_ff6f = { ab 07 [2] df 1f [2] 98 1d [2] df 0c [2] 91 00 [2] 9d 0a [2] 8a 01 [2] 91 4f [2] ac }

  condition:
    any of them
}