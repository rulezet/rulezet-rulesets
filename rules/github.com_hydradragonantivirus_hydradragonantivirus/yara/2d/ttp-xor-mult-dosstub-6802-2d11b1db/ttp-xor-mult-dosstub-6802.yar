rule TTP_XOR_MULT_DOSStub_6802 {
  strings:
    $key_6802 = { 3c 6a [2] 48 72 [2] 0f 70 [2] 48 61 [2] 06 6d [2] 0a 67 [2] 1d 6c [2] 06 22 [2] 3b }

  condition:
    any of them
}