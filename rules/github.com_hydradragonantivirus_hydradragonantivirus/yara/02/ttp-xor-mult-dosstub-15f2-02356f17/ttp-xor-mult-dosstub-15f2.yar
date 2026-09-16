rule TTP_XOR_MULT_DOSStub_15f2 {
  strings:
    $key_15f2 = { 41 9a [2] 35 82 [2] 72 80 [2] 35 91 [2] 7b 9d [2] 77 97 [2] 60 9c [2] 7b d2 [2] 46 }

  condition:
    any of them
}