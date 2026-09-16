rule TTP_XOR_MULT_DOSStub_6d75 {
  strings:
    $key_6d75 = { 39 1d [2] 4d 05 [2] 0a 07 [2] 4d 16 [2] 03 1a [2] 0f 10 [2] 18 1b [2] 03 55 [2] 3e }

  condition:
    any of them
}