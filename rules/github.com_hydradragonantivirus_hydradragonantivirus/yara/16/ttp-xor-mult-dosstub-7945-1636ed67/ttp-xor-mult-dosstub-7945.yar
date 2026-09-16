rule TTP_XOR_MULT_DOSStub_7945 {
  strings:
    $key_7945 = { 2d 2d [2] 59 35 [2] 1e 37 [2] 59 26 [2] 17 2a [2] 1b 20 [2] 0c 2b [2] 17 65 [2] 2a }

  condition:
    any of them
}