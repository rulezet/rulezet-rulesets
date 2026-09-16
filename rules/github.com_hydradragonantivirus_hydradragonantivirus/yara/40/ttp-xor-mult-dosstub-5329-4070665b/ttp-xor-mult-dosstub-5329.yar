rule TTP_XOR_MULT_DOSStub_5329 {
  strings:
    $key_5329 = { 07 41 [2] 73 59 [2] 34 5b [2] 73 4a [2] 3d 46 [2] 31 4c [2] 26 47 [2] 3d 09 [2] 00 }

  condition:
    any of them
}