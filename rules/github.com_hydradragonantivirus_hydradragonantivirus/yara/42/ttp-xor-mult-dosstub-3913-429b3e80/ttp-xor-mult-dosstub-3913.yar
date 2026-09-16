rule TTP_XOR_MULT_DOSStub_3913 {
  strings:
    $key_3913 = { 6d 7b [2] 19 63 [2] 5e 61 [2] 19 70 [2] 57 7c [2] 5b 76 [2] 4c 7d [2] 57 33 [2] 6a }

  condition:
    any of them
}