rule TTP_XOR_MULT_DOSStub_e053 {
  strings:
    $key_e053 = { b4 3b [2] c0 23 [2] 87 21 [2] c0 30 [2] 8e 3c [2] 82 36 [2] 95 3d [2] 8e 73 [2] b3 }

  condition:
    any of them
}