rule TTP_XOR_MULT_DOSStub_a72b {
  strings:
    $key_a72b = { f3 43 [2] 87 5b [2] c0 59 [2] 87 48 [2] c9 44 [2] c5 4e [2] d2 45 [2] c9 0b [2] f4 }

  condition:
    any of them
}