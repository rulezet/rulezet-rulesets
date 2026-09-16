rule TTP_XOR_MULT_DOSStub_4d29 {
  strings:
    $key_4d29 = { 19 41 [2] 6d 59 [2] 2a 5b [2] 6d 4a [2] 23 46 [2] 2f 4c [2] 38 47 [2] 23 09 [2] 1e }

  condition:
    any of them
}