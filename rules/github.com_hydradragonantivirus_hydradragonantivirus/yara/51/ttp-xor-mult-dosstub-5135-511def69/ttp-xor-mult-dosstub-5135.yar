rule TTP_XOR_MULT_DOSStub_5135 {
  strings:
    $key_5135 = { 05 5d [2] 71 45 [2] 36 47 [2] 71 56 [2] 3f 5a [2] 33 50 [2] 24 5b [2] 3f 15 [2] 02 }

  condition:
    any of them
}