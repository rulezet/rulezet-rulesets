rule TTP_XOR_MULT_DOSStub_b13c {
  strings:
    $key_b13c = { e5 54 [2] 91 4c [2] d6 4e [2] 91 5f [2] df 53 [2] d3 59 [2] c4 52 [2] df 1c [2] e2 }

  condition:
    any of them
}