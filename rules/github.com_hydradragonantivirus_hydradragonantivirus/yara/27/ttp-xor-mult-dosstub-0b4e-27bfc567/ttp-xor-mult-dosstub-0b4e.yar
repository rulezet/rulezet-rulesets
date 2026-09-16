rule TTP_XOR_MULT_DOSStub_0b4e {
  strings:
    $key_0b4e = { 5f 26 [2] 2b 3e [2] 6c 3c [2] 2b 2d [2] 65 21 [2] 69 2b [2] 7e 20 [2] 65 6e [2] 58 }

  condition:
    any of them
}