rule TTP_XOR_MULT_DOSStub_2b4e {
  strings:
    $key_2b4e = { 7f 26 [2] 0b 3e [2] 4c 3c [2] 0b 2d [2] 45 21 [2] 49 2b [2] 5e 20 [2] 45 6e [2] 78 }

  condition:
    any of them
}