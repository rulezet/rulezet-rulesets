rule TTP_XOR_MULT_DOSStub_5508 {
  strings:
    $key_5508 = { 01 60 [2] 75 78 [2] 32 7a [2] 75 6b [2] 3b 67 [2] 37 6d [2] 20 66 [2] 3b 28 [2] 06 }

  condition:
    any of them
}