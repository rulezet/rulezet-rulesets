rule TTP_XOR_MULT_DOSStub_b03c {
  strings:
    $key_b03c = { e4 54 [2] 90 4c [2] d7 4e [2] 90 5f [2] de 53 [2] d2 59 [2] c5 52 [2] de 1c [2] e3 }

  condition:
    any of them
}