rule TTP_XOR_MULT_DOSStub_e875 {
  strings:
    $key_e875 = { bc 1d [2] c8 05 [2] 8f 07 [2] c8 16 [2] 86 1a [2] 8a 10 [2] 9d 1b [2] 86 55 [2] bb }

  condition:
    any of them
}