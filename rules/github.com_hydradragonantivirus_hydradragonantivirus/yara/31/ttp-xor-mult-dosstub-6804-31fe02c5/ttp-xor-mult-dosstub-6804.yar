rule TTP_XOR_MULT_DOSStub_6804 {
  strings:
    $key_6804 = { 3c 6c [2] 48 74 [2] 0f 76 [2] 48 67 [2] 06 6b [2] 0a 61 [2] 1d 6a [2] 06 24 [2] 3b }

  condition:
    any of them
}