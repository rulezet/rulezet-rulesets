rule TTP_XOR_MULT_DOSStub_f404 {
  strings:
    $key_f404 = { a0 6c [2] d4 74 [2] 93 76 [2] d4 67 [2] 9a 6b [2] 96 61 [2] 81 6a [2] 9a 24 [2] a7 }

  condition:
    any of them
}