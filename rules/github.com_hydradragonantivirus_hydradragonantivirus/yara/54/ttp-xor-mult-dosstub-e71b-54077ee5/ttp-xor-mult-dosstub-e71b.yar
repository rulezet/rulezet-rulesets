rule TTP_XOR_MULT_DOSStub_e71b {
  strings:
    $key_e71b = { b3 73 [2] c7 6b [2] 80 69 [2] c7 78 [2] 89 74 [2] 85 7e [2] 92 75 [2] 89 3b [2] b4 }

  condition:
    any of them
}