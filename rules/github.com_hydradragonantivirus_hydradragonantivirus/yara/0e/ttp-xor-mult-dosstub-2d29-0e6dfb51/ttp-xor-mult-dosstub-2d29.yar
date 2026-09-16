rule TTP_XOR_MULT_DOSStub_2d29 {
  strings:
    $key_2d29 = { 79 41 [2] 0d 59 [2] 4a 5b [2] 0d 4a [2] 43 46 [2] 4f 4c [2] 58 47 [2] 43 09 [2] 7e }

  condition:
    any of them
}