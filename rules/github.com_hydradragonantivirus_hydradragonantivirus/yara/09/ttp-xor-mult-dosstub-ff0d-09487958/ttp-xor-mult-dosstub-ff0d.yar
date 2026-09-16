rule TTP_XOR_MULT_DOSStub_ff0d {
  strings:
    $key_ff0d = { ab 65 [2] df 7d [2] 98 7f [2] df 6e [2] 91 62 [2] 9d 68 [2] 8a 63 [2] 91 2d [2] ac }

  condition:
    any of them
}