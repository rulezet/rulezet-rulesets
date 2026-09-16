rule TTP_XOR_MULT_DOSStub_6d74 {
  strings:
    $key_6d74 = { 39 1c [2] 4d 04 [2] 0a 06 [2] 4d 17 [2] 03 1b [2] 0f 11 [2] 18 1a [2] 03 54 [2] 3e }

  condition:
    any of them
}