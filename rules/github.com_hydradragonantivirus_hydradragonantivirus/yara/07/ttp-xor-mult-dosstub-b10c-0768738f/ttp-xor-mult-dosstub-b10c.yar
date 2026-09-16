rule TTP_XOR_MULT_DOSStub_b10c {
  strings:
    $key_b10c = { e5 64 [2] 91 7c [2] d6 7e [2] 91 6f [2] df 63 [2] d3 69 [2] c4 62 [2] df 2c [2] e2 }

  condition:
    any of them
}