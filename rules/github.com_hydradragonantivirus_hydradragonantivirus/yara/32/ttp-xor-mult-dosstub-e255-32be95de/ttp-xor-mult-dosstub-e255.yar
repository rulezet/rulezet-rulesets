rule TTP_XOR_MULT_DOSStub_e255 {
  strings:
    $key_e255 = { b6 3d [2] c2 25 [2] 85 27 [2] c2 36 [2] 8c 3a [2] 80 30 [2] 97 3b [2] 8c 75 [2] b1 }

  condition:
    any of them
}