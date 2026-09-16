rule TTP_XOR_MULT_DOSStub_25f2 {
  strings:
    $key_25f2 = { 71 9a [2] 05 82 [2] 42 80 [2] 05 91 [2] 4b 9d [2] 47 97 [2] 50 9c [2] 4b d2 [2] 76 }

  condition:
    any of them
}