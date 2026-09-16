rule TTP_XOR_MULT_DOSStub_b1fe {
  strings:
    $key_b1fe = { e5 96 [2] 91 8e [2] d6 8c [2] 91 9d [2] df 91 [2] d3 9b [2] c4 90 [2] df de [2] e2 }

  condition:
    any of them
}