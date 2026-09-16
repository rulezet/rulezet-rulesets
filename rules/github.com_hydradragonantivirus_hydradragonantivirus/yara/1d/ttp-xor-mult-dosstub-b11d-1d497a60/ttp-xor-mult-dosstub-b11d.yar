rule TTP_XOR_MULT_DOSStub_b11d {
  strings:
    $key_b11d = { e5 75 [2] 91 6d [2] d6 6f [2] 91 7e [2] df 72 [2] d3 78 [2] c4 73 [2] df 3d [2] e2 }

  condition:
    any of them
}