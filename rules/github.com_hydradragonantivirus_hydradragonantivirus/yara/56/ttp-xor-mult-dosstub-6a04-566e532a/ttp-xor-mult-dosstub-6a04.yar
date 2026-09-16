rule TTP_XOR_MULT_DOSStub_6a04 {
  strings:
    $key_6a04 = { 3e 6c [2] 4a 74 [2] 0d 76 [2] 4a 67 [2] 04 6b [2] 08 61 [2] 1f 6a [2] 04 24 [2] 39 }

  condition:
    any of them
}