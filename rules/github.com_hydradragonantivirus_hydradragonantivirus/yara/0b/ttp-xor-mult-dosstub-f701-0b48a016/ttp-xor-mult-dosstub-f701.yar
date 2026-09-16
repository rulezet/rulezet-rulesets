rule TTP_XOR_MULT_DOSStub_f701 {
  strings:
    $key_f701 = { a3 69 [2] d7 71 [2] 90 73 [2] d7 62 [2] 99 6e [2] 95 64 [2] 82 6f [2] 99 21 [2] a4 }

  condition:
    any of them
}