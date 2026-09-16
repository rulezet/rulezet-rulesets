rule TTP_XOR_MULT_DOSStub_6d79 {
  strings:
    $key_6d79 = { 39 11 [2] 4d 09 [2] 0a 0b [2] 4d 1a [2] 03 16 [2] 0f 1c [2] 18 17 [2] 03 59 [2] 3e }

  condition:
    any of them
}