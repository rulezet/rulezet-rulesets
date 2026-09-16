rule TTP_XOR_MULT_DOSStub_5af9 {
  strings:
    $key_5af9 = { 0e 91 [2] 7a 89 [2] 3d 8b [2] 7a 9a [2] 34 96 [2] 38 9c [2] 2f 97 [2] 34 d9 [2] 09 }

  condition:
    any of them
}