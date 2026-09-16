rule TTP_XOR_MULT_DOSStub_e87e {
  strings:
    $key_e87e = { bc 16 [2] c8 0e [2] 8f 0c [2] c8 1d [2] 86 11 [2] 8a 1b [2] 9d 10 [2] 86 5e [2] bb }

  condition:
    any of them
}