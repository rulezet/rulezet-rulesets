rule TTP_XOR_MULT_DOSStub_24f2 {
  strings:
    $key_24f2 = { 70 9a [2] 04 82 [2] 43 80 [2] 04 91 [2] 4a 9d [2] 46 97 [2] 51 9c [2] 4a d2 [2] 77 }

  condition:
    any of them
}