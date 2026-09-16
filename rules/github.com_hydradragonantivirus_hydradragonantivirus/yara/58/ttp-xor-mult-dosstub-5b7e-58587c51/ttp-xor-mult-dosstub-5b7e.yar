rule TTP_XOR_MULT_DOSStub_5b7e {
  strings:
    $key_5b7e = { 0f 16 [2] 7b 0e [2] 3c 0c [2] 7b 1d [2] 35 11 [2] 39 1b [2] 2e 10 [2] 35 5e [2] 08 }

  condition:
    any of them
}