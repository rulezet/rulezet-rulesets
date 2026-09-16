rule TTP_XOR_MULT_DOSStub_e812 {
  strings:
    $key_e812 = { bc 7a [2] c8 62 [2] 8f 60 [2] c8 71 [2] 86 7d [2] 8a 77 [2] 9d 7c [2] 86 32 [2] bb }

  condition:
    any of them
}