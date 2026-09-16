rule TTP_XOR_MULT_DOSStub_e203 {
  strings:
    $key_e203 = { b6 6b [2] c2 73 [2] 85 71 [2] c2 60 [2] 8c 6c [2] 80 66 [2] 97 6d [2] 8c 23 [2] b1 }

  condition:
    any of them
}