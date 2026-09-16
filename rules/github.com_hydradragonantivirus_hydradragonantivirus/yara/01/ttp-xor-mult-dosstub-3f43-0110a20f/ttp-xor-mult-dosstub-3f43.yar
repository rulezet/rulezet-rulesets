rule TTP_XOR_MULT_DOSStub_3f43 {
  strings:
    $key_3f43 = { 6b 2b [2] 1f 33 [2] 58 31 [2] 1f 20 [2] 51 2c [2] 5d 26 [2] 4a 2d [2] 51 63 [2] 6c }

  condition:
    any of them
}