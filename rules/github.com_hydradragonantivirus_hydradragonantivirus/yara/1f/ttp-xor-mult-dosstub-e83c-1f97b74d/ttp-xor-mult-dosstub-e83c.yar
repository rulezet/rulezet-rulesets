rule TTP_XOR_MULT_DOSStub_e83c {
  strings:
    $key_e83c = { bc 54 [2] c8 4c [2] 8f 4e [2] c8 5f [2] 86 53 [2] 8a 59 [2] 9d 52 [2] 86 1c [2] bb }

  condition:
    any of them
}