rule TTP_XOR_MULT_DOSStub_a46b {
  strings:
    $key_a46b = { f0 03 [2] 84 1b [2] c3 19 [2] 84 08 [2] ca 04 [2] c6 0e [2] d1 05 [2] ca 4b [2] f7 }

  condition:
    any of them
}