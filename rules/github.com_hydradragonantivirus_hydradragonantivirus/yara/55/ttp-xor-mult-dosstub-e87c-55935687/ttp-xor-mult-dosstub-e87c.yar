rule TTP_XOR_MULT_DOSStub_e87c {
  strings:
    $key_e87c = { bc 14 [2] c8 0c [2] 8f 0e [2] c8 1f [2] 86 13 [2] 8a 19 [2] 9d 12 [2] 86 5c [2] bb }

  condition:
    any of them
}