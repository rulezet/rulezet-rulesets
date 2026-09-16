rule TTP_XOR_MULT_DOSStub_5805 {
  strings:
    $key_5805 = { 0c 6d [2] 78 75 [2] 3f 77 [2] 78 66 [2] 36 6a [2] 3a 60 [2] 2d 6b [2] 36 25 [2] 0b }

  condition:
    any of them
}