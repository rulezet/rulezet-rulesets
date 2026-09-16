rule TTP_XOR_MULT_DOSStub_6229 {
  strings:
    $key_6229 = { 36 41 [2] 42 59 [2] 05 5b [2] 42 4a [2] 0c 46 [2] 00 4c [2] 17 47 [2] 0c 09 [2] 31 }

  condition:
    any of them
}