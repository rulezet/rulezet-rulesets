rule TTP_XOR_MULT_DOSStub_ff4b {
  strings:
    $key_ff4b = { ab 23 [2] df 3b [2] 98 39 [2] df 28 [2] 91 24 [2] 9d 2e [2] 8a 25 [2] 91 6b [2] ac }

  condition:
    any of them
}