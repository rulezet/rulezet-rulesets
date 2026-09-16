rule TTP_XOR_MULT_DOSStub_2e73 {
  strings:
    $key_2e73 = { 7a 1b [2] 0e 03 [2] 49 01 [2] 0e 10 [2] 40 1c [2] 4c 16 [2] 5b 1d [2] 40 53 [2] 7d }

  condition:
    any of them
}