rule TTP_XOR_MULT_DOSStub_7823 {
  strings:
    $key_7823 = { 2c 4b [2] 58 53 [2] 1f 51 [2] 58 40 [2] 16 4c [2] 1a 46 [2] 0d 4d [2] 16 03 [2] 2b }

  condition:
    any of them
}