rule TTP_XOR_MULT_DOSStub_e222 {
  strings:
    $key_e222 = { b6 4a [2] c2 52 [2] 85 50 [2] c2 41 [2] 8c 4d [2] 80 47 [2] 97 4c [2] 8c 02 [2] b1 }

  condition:
    any of them
}