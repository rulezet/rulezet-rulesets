rule TTP_XOR_MULT_DOSStub_e353 {
  strings:
    $key_e353 = { b7 3b [2] c3 23 [2] 84 21 [2] c3 30 [2] 8d 3c [2] 81 36 [2] 96 3d [2] 8d 73 [2] b0 }

  condition:
    any of them
}