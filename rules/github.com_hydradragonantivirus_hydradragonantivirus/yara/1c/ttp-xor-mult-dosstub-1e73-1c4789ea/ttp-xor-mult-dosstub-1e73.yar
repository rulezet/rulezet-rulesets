rule TTP_XOR_MULT_DOSStub_1e73 {
  strings:
    $key_1e73 = { 4a 1b [2] 3e 03 [2] 79 01 [2] 3e 10 [2] 70 1c [2] 7c 16 [2] 6b 1d [2] 70 53 [2] 4d }

  condition:
    any of them
}