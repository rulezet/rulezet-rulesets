rule TTP_XOR_MULT_DOSStub_6d45 {
  strings:
    $key_6d45 = { 39 2d [2] 4d 35 [2] 0a 37 [2] 4d 26 [2] 03 2a [2] 0f 20 [2] 18 2b [2] 03 65 [2] 3e }

  condition:
    any of them
}