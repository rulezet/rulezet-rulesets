rule TTP_XOR_MULT_DOSStub_e275 {
  strings:
    $key_e275 = { b6 1d [2] c2 05 [2] 85 07 [2] c2 16 [2] 8c 1a [2] 80 10 [2] 97 1b [2] 8c 55 [2] b1 }

  condition:
    any of them
}