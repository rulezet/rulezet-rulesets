rule TTP_XOR_MULT_DOSStub_7b1e {
  strings:
    $key_7b1e = { 2f 76 [2] 5b 6e [2] 1c 6c [2] 5b 7d [2] 15 71 [2] 19 7b [2] 0e 70 [2] 15 3e [2] 28 }

  condition:
    any of them
}