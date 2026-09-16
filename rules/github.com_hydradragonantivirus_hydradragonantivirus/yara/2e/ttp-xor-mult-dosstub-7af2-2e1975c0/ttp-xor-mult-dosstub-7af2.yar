rule TTP_XOR_MULT_DOSStub_7af2 {
  strings:
    $key_7af2 = { 2e 9a [2] 5a 82 [2] 1d 80 [2] 5a 91 [2] 14 9d [2] 18 97 [2] 0f 9c [2] 14 d2 [2] 29 }

  condition:
    any of them
}