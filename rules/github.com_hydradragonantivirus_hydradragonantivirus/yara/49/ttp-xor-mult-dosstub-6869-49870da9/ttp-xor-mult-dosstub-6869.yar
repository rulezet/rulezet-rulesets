rule TTP_XOR_MULT_DOSStub_6869 {
  strings:
    $key_6869 = { 3c 01 [2] 48 19 [2] 0f 1b [2] 48 0a [2] 06 06 [2] 0a 0c [2] 1d 07 [2] 06 49 [2] 3b }

  condition:
    any of them
}