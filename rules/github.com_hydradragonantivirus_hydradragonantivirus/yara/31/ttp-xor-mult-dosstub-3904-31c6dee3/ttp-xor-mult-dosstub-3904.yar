rule TTP_XOR_MULT_DOSStub_3904 {
  strings:
    $key_3904 = { 6d 6c [2] 19 74 [2] 5e 76 [2] 19 67 [2] 57 6b [2] 5b 61 [2] 4c 6a [2] 57 24 [2] 6a }

  condition:
    any of them
}