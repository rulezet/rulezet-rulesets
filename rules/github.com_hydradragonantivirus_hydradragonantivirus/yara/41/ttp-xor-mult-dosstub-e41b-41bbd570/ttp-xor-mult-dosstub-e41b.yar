rule TTP_XOR_MULT_DOSStub_e41b {
  strings:
    $key_e41b = { b0 73 [2] c4 6b [2] 83 69 [2] c4 78 [2] 8a 74 [2] 86 7e [2] 91 75 [2] 8a 3b [2] b7 }

  condition:
    any of them
}