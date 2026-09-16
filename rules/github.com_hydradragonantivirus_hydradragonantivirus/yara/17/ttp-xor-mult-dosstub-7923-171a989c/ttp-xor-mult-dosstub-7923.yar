rule TTP_XOR_MULT_DOSStub_7923 {
  strings:
    $key_7923 = { 2d 4b [2] 59 53 [2] 1e 51 [2] 59 40 [2] 17 4c [2] 1b 46 [2] 0c 4d [2] 17 03 [2] 2a }

  condition:
    any of them
}