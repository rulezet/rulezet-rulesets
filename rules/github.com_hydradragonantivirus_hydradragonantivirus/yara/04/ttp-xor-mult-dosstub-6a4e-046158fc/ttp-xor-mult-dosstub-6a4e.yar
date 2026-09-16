rule TTP_XOR_MULT_DOSStub_6a4e {
  strings:
    $key_6a4e = { 3e 26 [2] 4a 3e [2] 0d 3c [2] 4a 2d [2] 04 21 [2] 08 2b [2] 1f 20 [2] 04 6e [2] 39 }

  condition:
    any of them
}