rule TTP_XOR_MULT_DOSStub_ff0b {
  strings:
    $key_ff0b = { ab 63 [2] df 7b [2] 98 79 [2] df 68 [2] 91 64 [2] 9d 6e [2] 8a 65 [2] 91 2b [2] ac }

  condition:
    any of them
}