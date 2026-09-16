rule TTP_XOR_MULT_DOSStub_0129 {
  strings:
    $key_0129 = { 55 41 [2] 21 59 [2] 66 5b [2] 21 4a [2] 6f 46 [2] 63 4c [2] 74 47 [2] 6f 09 [2] 52 }

  condition:
    any of them
}