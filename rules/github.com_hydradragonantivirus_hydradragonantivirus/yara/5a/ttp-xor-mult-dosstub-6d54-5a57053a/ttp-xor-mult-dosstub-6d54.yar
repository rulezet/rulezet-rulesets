rule TTP_XOR_MULT_DOSStub_6d54 {
  strings:
    $key_6d54 = { 39 3c [2] 4d 24 [2] 0a 26 [2] 4d 37 [2] 03 3b [2] 0f 31 [2] 18 3a [2] 03 74 [2] 3e }

  condition:
    any of them
}