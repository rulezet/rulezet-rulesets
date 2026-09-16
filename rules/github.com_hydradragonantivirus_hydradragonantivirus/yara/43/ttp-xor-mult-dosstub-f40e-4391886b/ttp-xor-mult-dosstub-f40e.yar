rule TTP_XOR_MULT_DOSStub_f40e {
  strings:
    $key_f40e = { a0 66 [2] d4 7e [2] 93 7c [2] d4 6d [2] 9a 61 [2] 96 6b [2] 81 60 [2] 9a 2e [2] a7 }

  condition:
    any of them
}