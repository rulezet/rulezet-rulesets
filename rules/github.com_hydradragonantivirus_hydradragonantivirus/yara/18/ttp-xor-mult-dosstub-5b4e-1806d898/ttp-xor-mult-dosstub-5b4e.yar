rule TTP_XOR_MULT_DOSStub_5b4e {
  strings:
    $key_5b4e = { 0f 26 [2] 7b 3e [2] 3c 3c [2] 7b 2d [2] 35 21 [2] 39 2b [2] 2e 20 [2] 35 6e [2] 08 }

  condition:
    any of them
}