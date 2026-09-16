rule TTP_XOR_MULT_DOSStub_7d23 {
  strings:
    $key_7d23 = { 29 4b [2] 5d 53 [2] 1a 51 [2] 5d 40 [2] 13 4c [2] 1f 46 [2] 08 4d [2] 13 03 [2] 2e }

  condition:
    any of them
}