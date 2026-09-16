rule TTP_XOR_MULT_DOSStub_a12b {
  strings:
    $key_a12b = { f5 43 [2] 81 5b [2] c6 59 [2] 81 48 [2] cf 44 [2] c3 4e [2] d4 45 [2] cf 0b [2] f2 }

  condition:
    any of them
}