rule TTP_XOR_MULT_DOSStub_2de8 {
  strings:
    $key_2de8 = { 79 80 [2] 0d 98 [2] 4a 9a [2] 0d 8b [2] 43 87 [2] 4f 8d [2] 58 86 [2] 43 c8 [2] 7e }

  condition:
    any of them
}