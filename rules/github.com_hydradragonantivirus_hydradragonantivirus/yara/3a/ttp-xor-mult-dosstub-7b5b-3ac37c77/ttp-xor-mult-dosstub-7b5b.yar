rule TTP_XOR_MULT_DOSStub_7b5b {
  strings:
    $key_7b5b = { 2f 33 [2] 5b 2b [2] 1c 29 [2] 5b 38 [2] 15 34 [2] 19 3e [2] 0e 35 [2] 15 7b [2] 28 }

  condition:
    any of them
}