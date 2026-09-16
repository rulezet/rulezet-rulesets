rule TTP_XOR_MULT_DOSStub_7949 {
  strings:
    $key_7949 = { 2d 21 [2] 59 39 [2] 1e 3b [2] 59 2a [2] 17 26 [2] 1b 2c [2] 0c 27 [2] 17 69 [2] 2a }

  condition:
    any of them
}