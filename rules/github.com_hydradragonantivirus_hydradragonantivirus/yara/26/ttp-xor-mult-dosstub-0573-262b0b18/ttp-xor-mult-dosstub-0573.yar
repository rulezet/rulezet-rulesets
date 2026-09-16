rule TTP_XOR_MULT_DOSStub_0573 {
  strings:
    $key_0573 = { 51 1b [2] 25 03 [2] 62 01 [2] 25 10 [2] 6b 1c [2] 67 16 [2] 70 1d [2] 6b 53 [2] 56 }

  condition:
    any of them
}