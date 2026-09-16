rule TTP_XOR_MULT_DOSStub_6a09 {
  strings:
    $key_6a09 = { 3e 61 [2] 4a 79 [2] 0d 7b [2] 4a 6a [2] 04 66 [2] 08 6c [2] 1f 67 [2] 04 29 [2] 39 }

  condition:
    any of them
}