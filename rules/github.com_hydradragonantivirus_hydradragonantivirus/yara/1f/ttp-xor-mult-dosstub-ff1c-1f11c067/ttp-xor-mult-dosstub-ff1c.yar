rule TTP_XOR_MULT_DOSStub_ff1c {
  strings:
    $key_ff1c = { ab 74 [2] df 6c [2] 98 6e [2] df 7f [2] 91 73 [2] 9d 79 [2] 8a 72 [2] 91 3c [2] ac }

  condition:
    any of them
}