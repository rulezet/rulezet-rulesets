rule TTP_XOR_MULT_DOSStub_652e {
  strings:
    $key_652e = { 31 46 [2] 45 5e [2] 02 5c [2] 45 4d [2] 0b 41 [2] 07 4b [2] 10 40 [2] 0b 0e [2] 36 }

  condition:
    any of them
}