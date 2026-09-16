rule TTP_XOR_MULT_DOSStub_e8e8 {
  strings:
    $key_e8e8 = { bc 80 [2] c8 98 [2] 8f 9a [2] c8 8b [2] 86 87 [2] 8a 8d [2] 9d 86 [2] 86 c8 [2] bb }

  condition:
    any of them
}