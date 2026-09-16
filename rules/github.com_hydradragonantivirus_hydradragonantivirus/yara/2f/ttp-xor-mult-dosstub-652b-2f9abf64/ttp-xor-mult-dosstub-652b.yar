rule TTP_XOR_MULT_DOSStub_652b {
  strings:
    $key_652b = { 31 43 [2] 45 5b [2] 02 59 [2] 45 48 [2] 0b 44 [2] 07 4e [2] 10 45 [2] 0b 0b [2] 36 }

  condition:
    any of them
}