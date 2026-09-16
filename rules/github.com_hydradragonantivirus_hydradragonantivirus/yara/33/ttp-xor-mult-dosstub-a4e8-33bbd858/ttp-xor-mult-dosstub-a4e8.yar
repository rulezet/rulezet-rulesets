rule TTP_XOR_MULT_DOSStub_a4e8 {
  strings:
    $key_a4e8 = { f0 80 [2] 84 98 [2] c3 9a [2] 84 8b [2] ca 87 [2] c6 8d [2] d1 86 [2] ca c8 [2] f7 }

  condition:
    any of them
}