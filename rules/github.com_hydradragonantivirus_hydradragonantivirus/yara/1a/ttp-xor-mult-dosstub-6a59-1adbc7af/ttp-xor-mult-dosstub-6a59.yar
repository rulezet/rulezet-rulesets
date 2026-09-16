rule TTP_XOR_MULT_DOSStub_6a59 {
  strings:
    $key_6a59 = { 3e 31 [2] 4a 29 [2] 0d 2b [2] 4a 3a [2] 04 36 [2] 08 3c [2] 1f 37 [2] 04 79 [2] 39 }

  condition:
    any of them
}