rule TTP_XOR_MULT_DOSStub_2b6e {
  strings:
    $key_2b6e = { 7f 06 [2] 0b 1e [2] 4c 1c [2] 0b 0d [2] 45 01 [2] 49 0b [2] 5e 00 [2] 45 4e [2] 78 }

  condition:
    any of them
}