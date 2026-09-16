rule TTP_XOR_MULT_DOSStub_7925 {
  strings:
    $key_7925 = { 2d 4d [2] 59 55 [2] 1e 57 [2] 59 46 [2] 17 4a [2] 1b 40 [2] 0c 4b [2] 17 05 [2] 2a }

  condition:
    any of them
}