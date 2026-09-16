rule TTP_XOR_MULT_DOSStub_e848 {
  strings:
    $key_e848 = { bc 20 [2] c8 38 [2] 8f 3a [2] c8 2b [2] 86 27 [2] 8a 2d [2] 9d 26 [2] 86 68 [2] bb }

  condition:
    any of them
}