rule TTP_XOR_MULT_DOSStub_0a4e {
  strings:
    $key_0a4e = { 5e 26 [2] 2a 3e [2] 6d 3c [2] 2a 2d [2] 64 21 [2] 68 2b [2] 7f 20 [2] 64 6e [2] 59 }

  condition:
    any of them
}