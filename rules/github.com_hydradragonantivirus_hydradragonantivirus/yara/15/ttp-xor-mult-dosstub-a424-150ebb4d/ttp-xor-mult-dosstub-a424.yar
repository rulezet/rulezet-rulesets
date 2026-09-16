rule TTP_XOR_MULT_DOSStub_a424 {
  strings:
    $key_a424 = { f0 4c [2] 84 54 [2] c3 56 [2] 84 47 [2] ca 4b [2] c6 41 [2] d1 4a [2] ca 04 [2] f7 }

  condition:
    any of them
}