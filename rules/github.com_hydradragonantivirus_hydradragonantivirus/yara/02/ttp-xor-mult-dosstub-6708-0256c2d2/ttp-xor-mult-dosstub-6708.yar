rule TTP_XOR_MULT_DOSStub_6708 {
  strings:
    $key_6708 = { 33 60 [2] 47 78 [2] 00 7a [2] 47 6b [2] 09 67 [2] 05 6d [2] 12 66 [2] 09 28 [2] 34 }

  condition:
    any of them
}