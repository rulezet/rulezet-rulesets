rule TTP_XOR_MULT_DOSStub_e205 {
  strings:
    $key_e205 = { b6 6d [2] c2 75 [2] 85 77 [2] c2 66 [2] 8c 6a [2] 80 60 [2] 97 6b [2] 8c 25 [2] b1 }

  condition:
    any of them
}