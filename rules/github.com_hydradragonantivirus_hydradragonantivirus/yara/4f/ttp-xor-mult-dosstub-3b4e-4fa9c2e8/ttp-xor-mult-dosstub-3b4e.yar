rule TTP_XOR_MULT_DOSStub_3b4e {
  strings:
    $key_3b4e = { 6f 26 [2] 1b 3e [2] 5c 3c [2] 1b 2d [2] 55 21 [2] 59 2b [2] 4e 20 [2] 55 6e [2] 68 }

  condition:
    any of them
}