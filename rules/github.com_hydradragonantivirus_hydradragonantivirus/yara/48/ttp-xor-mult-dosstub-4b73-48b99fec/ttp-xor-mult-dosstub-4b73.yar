rule TTP_XOR_MULT_DOSStub_4b73 {
  strings:
    $key_4b73 = { 1f 1b [2] 6b 03 [2] 2c 01 [2] 6b 10 [2] 25 1c [2] 29 16 [2] 3e 1d [2] 25 53 [2] 18 }

  condition:
    any of them
}