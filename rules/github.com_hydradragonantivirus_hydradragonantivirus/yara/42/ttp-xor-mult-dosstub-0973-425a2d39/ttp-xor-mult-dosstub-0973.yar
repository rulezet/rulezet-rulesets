rule TTP_XOR_MULT_DOSStub_0973 {
  strings:
    $key_0973 = { 5d 1b [2] 29 03 [2] 6e 01 [2] 29 10 [2] 67 1c [2] 6b 16 [2] 7c 1d [2] 67 53 [2] 5a }

  condition:
    any of them
}