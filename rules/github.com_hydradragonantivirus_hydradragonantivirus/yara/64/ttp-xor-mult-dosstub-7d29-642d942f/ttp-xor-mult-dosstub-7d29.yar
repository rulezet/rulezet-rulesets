rule TTP_XOR_MULT_DOSStub_7d29 {
  strings:
    $key_7d29 = { 29 41 [2] 5d 59 [2] 1a 5b [2] 5d 4a [2] 13 46 [2] 1f 4c [2] 08 47 [2] 13 09 [2] 2e }

  condition:
    any of them
}