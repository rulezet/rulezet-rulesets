rule TTP_XOR_MULT_DOSStub_3945 {
  strings:
    $key_3945 = { 6d 2d [2] 19 35 [2] 5e 37 [2] 19 26 [2] 57 2a [2] 5b 20 [2] 4c 2b [2] 57 65 [2] 6a }

  condition:
    any of them
}