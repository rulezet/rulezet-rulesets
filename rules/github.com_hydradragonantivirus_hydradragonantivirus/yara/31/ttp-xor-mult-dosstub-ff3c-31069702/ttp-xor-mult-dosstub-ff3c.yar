rule TTP_XOR_MULT_DOSStub_ff3c {
  strings:
    $key_ff3c = { ab 54 [2] df 4c [2] 98 4e [2] df 5f [2] 91 53 [2] 9d 59 [2] 8a 52 [2] 91 1c [2] ac }

  condition:
    any of them
}