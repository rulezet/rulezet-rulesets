rule TTP_XOR_MULT_DOSStub_f403 {
  strings:
    $key_f403 = { a0 6b [2] d4 73 [2] 93 71 [2] d4 60 [2] 9a 6c [2] 96 66 [2] 81 6d [2] 9a 23 [2] a7 }

  condition:
    any of them
}