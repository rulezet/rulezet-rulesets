rule TTP_XOR_MULT_DOSStub_4d28 {
  strings:
    $key_4d28 = { 19 40 [2] 6d 58 [2] 2a 5a [2] 6d 4b [2] 23 47 [2] 2f 4d [2] 38 46 [2] 23 08 [2] 1e }

  condition:
    any of them
}