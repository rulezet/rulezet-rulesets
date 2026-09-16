rule TTP_XOR_MULT_DOSStub_f21b {
  strings:
    $key_f21b = { a6 73 [2] d2 6b [2] 95 69 [2] d2 78 [2] 9c 74 [2] 90 7e [2] 87 75 [2] 9c 3b [2] a1 }

  condition:
    any of them
}