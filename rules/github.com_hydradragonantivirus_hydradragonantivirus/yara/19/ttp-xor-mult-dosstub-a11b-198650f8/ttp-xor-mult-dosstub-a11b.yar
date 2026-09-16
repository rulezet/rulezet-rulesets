rule TTP_XOR_MULT_DOSStub_a11b {
  strings:
    $key_a11b = { f5 73 [2] 81 6b [2] c6 69 [2] 81 78 [2] cf 74 [2] c3 7e [2] d4 75 [2] cf 3b [2] f2 }

  condition:
    any of them
}