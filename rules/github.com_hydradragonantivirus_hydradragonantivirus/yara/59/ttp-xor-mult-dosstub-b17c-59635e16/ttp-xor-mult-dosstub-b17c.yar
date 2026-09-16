rule TTP_XOR_MULT_DOSStub_b17c {
  strings:
    $key_b17c = { e5 14 [2] 91 0c [2] d6 0e [2] 91 1f [2] df 13 [2] d3 19 [2] c4 12 [2] df 5c [2] e2 }

  condition:
    any of them
}