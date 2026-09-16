rule TTP_XOR_MULT_DOSStub_5b73 {
  strings:
    $key_5b73 = { 0f 1b [2] 7b 03 [2] 3c 01 [2] 7b 10 [2] 35 1c [2] 39 16 [2] 2e 1d [2] 35 53 [2] 08 }

  condition:
    any of them
}