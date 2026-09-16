rule TTP_XOR_MULT_DOSStub_a40b {
  strings:
    $key_a40b = { f0 63 [2] 84 7b [2] c3 79 [2] 84 68 [2] ca 64 [2] c6 6e [2] d1 65 [2] ca 2b [2] f7 }

  condition:
    any of them
}