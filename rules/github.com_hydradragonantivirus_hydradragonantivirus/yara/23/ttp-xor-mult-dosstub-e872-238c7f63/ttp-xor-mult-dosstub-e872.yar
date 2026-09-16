rule TTP_XOR_MULT_DOSStub_e872 {
  strings:
    $key_e872 = { bc 1a [2] c8 02 [2] 8f 00 [2] c8 11 [2] 86 1d [2] 8a 17 [2] 9d 1c [2] 86 52 [2] bb }

  condition:
    any of them
}