rule TTP_XOR_MULT_DOSStub_f11b {
  strings:
    $key_f11b = { a5 73 [2] d1 6b [2] 96 69 [2] d1 78 [2] 9f 74 [2] 93 7e [2] 84 75 [2] 9f 3b [2] a2 }

  condition:
    any of them
}