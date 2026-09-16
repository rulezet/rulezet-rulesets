rule TTP_XOR_MULT_DOSStub_5d28 {
  strings:
    $key_5d28 = { 09 40 [2] 7d 58 [2] 3a 5a [2] 7d 4b [2] 33 47 [2] 3f 4d [2] 28 46 [2] 33 08 [2] 0e }

  condition:
    any of them
}