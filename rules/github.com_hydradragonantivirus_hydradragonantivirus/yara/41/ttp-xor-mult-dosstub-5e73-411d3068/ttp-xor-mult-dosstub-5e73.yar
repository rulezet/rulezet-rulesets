rule TTP_XOR_MULT_DOSStub_5e73 {
  strings:
    $key_5e73 = { 0a 1b [2] 7e 03 [2] 39 01 [2] 7e 10 [2] 30 1c [2] 3c 16 [2] 2b 1d [2] 30 53 [2] 0d }

  condition:
    any of them
}