rule TTP_XOR_MULT_DOSStub_1f43 {
  strings:
    $key_1f43 = { 4b 2b [2] 3f 33 [2] 78 31 [2] 3f 20 [2] 71 2c [2] 7d 26 [2] 6a 2d [2] 71 63 [2] 4c }

  condition:
    any of them
}