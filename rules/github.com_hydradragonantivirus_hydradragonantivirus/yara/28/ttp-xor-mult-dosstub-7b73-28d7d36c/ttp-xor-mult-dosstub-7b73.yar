rule TTP_XOR_MULT_DOSStub_7b73 {
  strings:
    $key_7b73 = { 2f 1b [2] 5b 03 [2] 1c 01 [2] 5b 10 [2] 15 1c [2] 19 16 [2] 0e 1d [2] 15 53 [2] 28 }

  condition:
    any of them
}