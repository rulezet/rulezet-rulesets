rule TTP_XOR_MULT_DOSStub_ff7c {
  strings:
    $key_ff7c = { ab 14 [2] df 0c [2] 98 0e [2] df 1f [2] 91 13 [2] 9d 19 [2] 8a 12 [2] 91 5c [2] ac }

  condition:
    any of them
}