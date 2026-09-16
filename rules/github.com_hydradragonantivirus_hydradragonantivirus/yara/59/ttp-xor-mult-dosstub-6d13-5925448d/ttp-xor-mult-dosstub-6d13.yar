rule TTP_XOR_MULT_DOSStub_6d13 {
  strings:
    $key_6d13 = { 39 7b [2] 4d 63 [2] 0a 61 [2] 4d 70 [2] 03 7c [2] 0f 76 [2] 18 7d [2] 03 33 [2] 3e }

  condition:
    any of them
}