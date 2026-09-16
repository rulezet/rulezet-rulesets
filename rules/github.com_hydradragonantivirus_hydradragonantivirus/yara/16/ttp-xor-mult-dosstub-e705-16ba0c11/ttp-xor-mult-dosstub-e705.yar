rule TTP_XOR_MULT_DOSStub_e705 {
  strings:
    $key_e705 = { b3 6d [2] c7 75 [2] 80 77 [2] c7 66 [2] 89 6a [2] 85 60 [2] 92 6b [2] 89 25 [2] b4 }

  condition:
    any of them
}