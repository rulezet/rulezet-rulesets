rule TTP_XOR_MULT_DOSStub_63f4 {
  strings:
    $key_63f4 = { 37 9c [2] 43 84 [2] 04 86 [2] 43 97 [2] 0d 9b [2] 01 91 [2] 16 9a [2] 0d d4 [2] 30 }

  condition:
    any of them
}