rule TTP_XOR_MULT_DOSStub_e53e {
  strings:
    $key_e53e = { b1 56 [2] c5 4e [2] 82 4c [2] c5 5d [2] 8b 51 [2] 87 5b [2] 90 50 [2] 8b 1e [2] b6 }

  condition:
    any of them
}