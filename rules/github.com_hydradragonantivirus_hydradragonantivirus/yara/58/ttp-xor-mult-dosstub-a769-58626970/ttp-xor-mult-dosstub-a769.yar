rule TTP_XOR_MULT_DOSStub_a769 {
  strings:
    $key_a769 = { f3 01 [2] 87 19 [2] c0 1b [2] 87 0a [2] c9 06 [2] c5 0c [2] d2 07 [2] c9 49 [2] f4 }

  condition:
    any of them
}