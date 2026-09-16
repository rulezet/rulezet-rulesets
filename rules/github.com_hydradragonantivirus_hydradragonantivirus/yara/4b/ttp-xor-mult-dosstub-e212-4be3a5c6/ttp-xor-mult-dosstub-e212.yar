rule TTP_XOR_MULT_DOSStub_e212 {
  strings:
    $key_e212 = { b6 7a [2] c2 62 [2] 85 60 [2] c2 71 [2] 8c 7d [2] 80 77 [2] 97 7c [2] 8c 32 [2] b1 }

  condition:
    any of them
}