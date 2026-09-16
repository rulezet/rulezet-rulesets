rule TTP_XOR_MULT_DOSStub_b173 {
  strings:
    $key_b173 = { e5 1b [2] 91 03 [2] d6 01 [2] 91 10 [2] df 1c [2] d3 16 [2] c4 1d [2] df 53 [2] e2 }

  condition:
    any of them
}