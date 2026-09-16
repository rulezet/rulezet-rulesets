rule TTP_XOR_MULT_DOSStub_e728 {
  strings:
    $key_e728 = { b3 40 [2] c7 58 [2] 80 5a [2] c7 4b [2] 89 47 [2] 85 4d [2] 92 46 [2] 89 08 [2] b4 }

  condition:
    any of them
}