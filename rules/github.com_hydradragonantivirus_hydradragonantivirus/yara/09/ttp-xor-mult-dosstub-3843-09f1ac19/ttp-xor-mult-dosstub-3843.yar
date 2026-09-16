rule TTP_XOR_MULT_DOSStub_3843 {
  strings:
    $key_3843 = { 6c 2b [2] 18 33 [2] 5f 31 [2] 18 20 [2] 56 2c [2] 5a 26 [2] 4d 2d [2] 56 63 [2] 6b }

  condition:
    any of them
}