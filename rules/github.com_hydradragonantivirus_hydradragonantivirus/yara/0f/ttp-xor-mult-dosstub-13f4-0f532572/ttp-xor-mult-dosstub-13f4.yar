rule TTP_XOR_MULT_DOSStub_13f4 {
  strings:
    $key_13f4 = { 47 9c [2] 33 84 [2] 74 86 [2] 33 97 [2] 7d 9b [2] 71 91 [2] 66 9a [2] 7d d4 [2] 40 }

  condition:
    any of them
}