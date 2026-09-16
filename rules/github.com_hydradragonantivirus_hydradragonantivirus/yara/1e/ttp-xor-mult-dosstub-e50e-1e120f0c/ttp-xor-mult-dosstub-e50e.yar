rule TTP_XOR_MULT_DOSStub_e50e {
  strings:
    $key_e50e = { b1 66 [2] c5 7e [2] 82 7c [2] c5 6d [2] 8b 61 [2] 87 6b [2] 90 60 [2] 8b 2e [2] b6 }

  condition:
    any of them
}