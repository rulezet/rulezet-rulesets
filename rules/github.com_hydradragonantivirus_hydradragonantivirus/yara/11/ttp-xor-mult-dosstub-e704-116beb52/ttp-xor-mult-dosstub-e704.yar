rule TTP_XOR_MULT_DOSStub_e704 {
  strings:
    $key_e704 = { b3 6c [2] c7 74 [2] 80 76 [2] c7 67 [2] 89 6b [2] 85 61 [2] 92 6a [2] 89 24 [2] b4 }

  condition:
    any of them
}