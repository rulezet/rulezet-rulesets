rule TTP_XOR_MULT_DOSStub_e722 {
  strings:
    $key_e722 = { b3 4a [2] c7 52 [2] 80 50 [2] c7 41 [2] 89 4d [2] 85 47 [2] 92 4c [2] 89 02 [2] b4 }

  condition:
    any of them
}