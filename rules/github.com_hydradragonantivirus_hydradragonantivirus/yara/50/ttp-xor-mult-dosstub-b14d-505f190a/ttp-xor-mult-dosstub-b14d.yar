rule TTP_XOR_MULT_DOSStub_b14d {
  strings:
    $key_b14d = { e5 25 [2] 91 3d [2] d6 3f [2] 91 2e [2] df 22 [2] d3 28 [2] c4 23 [2] df 6d [2] e2 }

  condition:
    any of them
}