rule TTP_XOR_MULT_DOSStub_651e {
  strings:
    $key_651e = { 31 76 [2] 45 6e [2] 02 6c [2] 45 7d [2] 0b 71 [2] 07 7b [2] 10 70 [2] 0b 3e [2] 36 }

  condition:
    any of them
}