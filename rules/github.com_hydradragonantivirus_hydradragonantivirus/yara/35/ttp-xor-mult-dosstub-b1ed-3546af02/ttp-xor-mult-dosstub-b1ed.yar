rule TTP_XOR_MULT_DOSStub_b1ed {
  strings:
    $key_b1ed = { e5 85 [2] 91 9d [2] d6 9f [2] 91 8e [2] df 82 [2] d3 88 [2] c4 83 [2] df cd [2] e2 }

  condition:
    any of them
}