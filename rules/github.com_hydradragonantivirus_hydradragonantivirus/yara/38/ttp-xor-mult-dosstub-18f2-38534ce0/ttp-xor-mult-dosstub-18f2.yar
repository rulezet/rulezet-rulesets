rule TTP_XOR_MULT_DOSStub_18f2 {
  strings:
    $key_18f2 = { 4c 9a [2] 38 82 [2] 7f 80 [2] 38 91 [2] 76 9d [2] 7a 97 [2] 6d 9c [2] 76 d2 [2] 4b }

  condition:
    any of them
}