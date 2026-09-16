rule TTP_XOR_MULT_DOSStub_6302 {
  strings:
    $key_6302 = { 37 6a [2] 43 72 [2] 04 70 [2] 43 61 [2] 0d 6d [2] 01 67 [2] 16 6c [2] 0d 22 [2] 30 }

  condition:
    any of them
}