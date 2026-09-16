rule TTP_XOR_MULT_DOSStub_7129 {
  strings:
    $key_7129 = { 25 41 [2] 51 59 [2] 16 5b [2] 51 4a [2] 1f 46 [2] 13 4c [2] 04 47 [2] 1f 09 [2] 22 }

  condition:
    any of them
}