rule TTP_XOR_MULT_DOSStub_e8e3 {
  strings:
    $key_e8e3 = { bc 8b [2] c8 93 [2] 8f 91 [2] c8 80 [2] 86 8c [2] 8a 86 [2] 9d 8d [2] 86 c3 [2] bb }

  condition:
    any of them
}