rule TTP_XOR_MULT_DOSStub_e810 {
  strings:
    $key_e810 = { bc 78 [2] c8 60 [2] 8f 62 [2] c8 73 [2] 86 7f [2] 8a 75 [2] 9d 7e [2] 86 30 [2] bb }

  condition:
    any of them
}