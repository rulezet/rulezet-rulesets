rule TTP_XOR_MULT_DOSStub_726e {
  strings:
    $key_726e = { 26 06 [2] 52 1e [2] 15 1c [2] 52 0d [2] 1c 01 [2] 10 0b [2] 07 00 [2] 1c 4e [2] 21 }

  condition:
    any of them
}