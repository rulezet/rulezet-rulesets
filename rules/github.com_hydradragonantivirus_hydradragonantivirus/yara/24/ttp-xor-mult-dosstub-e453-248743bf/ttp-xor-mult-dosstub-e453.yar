rule TTP_XOR_MULT_DOSStub_e453 {
  strings:
    $key_e453 = { b0 3b [2] c4 23 [2] 83 21 [2] c4 30 [2] 8a 3c [2] 86 36 [2] 91 3d [2] 8a 73 [2] b7 }

  condition:
    any of them
}