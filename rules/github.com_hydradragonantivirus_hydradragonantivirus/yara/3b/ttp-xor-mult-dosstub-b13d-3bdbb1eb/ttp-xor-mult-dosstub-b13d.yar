rule TTP_XOR_MULT_DOSStub_b13d {
  strings:
    $key_b13d = { e5 55 [2] 91 4d [2] d6 4f [2] 91 5e [2] df 52 [2] d3 58 [2] c4 53 [2] df 1d [2] e2 }

  condition:
    any of them
}