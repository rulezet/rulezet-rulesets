rule TTP_XOR_MULT_DOSStub_45f2 {
  strings:
    $key_45f2 = { 11 9a [2] 65 82 [2] 22 80 [2] 65 91 [2] 2b 9d [2] 27 97 [2] 30 9c [2] 2b d2 [2] 16 }

  condition:
    any of them
}