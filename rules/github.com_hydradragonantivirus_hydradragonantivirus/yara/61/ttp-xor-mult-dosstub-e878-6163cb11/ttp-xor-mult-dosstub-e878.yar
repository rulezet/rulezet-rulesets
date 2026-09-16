rule TTP_XOR_MULT_DOSStub_e878 {
  strings:
    $key_e878 = { bc 10 [2] c8 08 [2] 8f 0a [2] c8 1b [2] 86 17 [2] 8a 1d [2] 9d 16 [2] 86 58 [2] bb }

  condition:
    any of them
}