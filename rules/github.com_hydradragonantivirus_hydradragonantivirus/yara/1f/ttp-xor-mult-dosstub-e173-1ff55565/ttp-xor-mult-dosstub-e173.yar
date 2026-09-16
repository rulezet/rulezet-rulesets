rule TTP_XOR_MULT_DOSStub_e173 {
  strings:
    $key_e173 = { b5 1b [2] c1 03 [2] 86 01 [2] c1 10 [2] 8f 1c [2] 83 16 [2] 94 1d [2] 8f 53 [2] b2 }

  condition:
    any of them
}