rule TTP_XOR_MULT_DOSStub_7b7e {
  strings:
    $key_7b7e = { 2f 16 [2] 5b 0e [2] 1c 0c [2] 5b 1d [2] 15 11 [2] 19 1b [2] 0e 10 [2] 15 5e [2] 28 }

  condition:
    any of them
}