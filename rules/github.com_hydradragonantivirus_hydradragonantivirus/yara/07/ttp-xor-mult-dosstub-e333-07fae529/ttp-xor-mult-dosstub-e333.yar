rule TTP_XOR_MULT_DOSStub_e333 {
  strings:
    $key_e333 = { b7 5b [2] c3 43 [2] 84 41 [2] c3 50 [2] 8d 5c [2] 81 56 [2] 96 5d [2] 8d 13 [2] b0 }

  condition:
    any of them
}