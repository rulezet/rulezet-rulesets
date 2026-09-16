rule TTP_XOR_MULT_DOSStub_f706 {
  strings:
    $key_f706 = { a3 6e [2] d7 76 [2] 90 74 [2] d7 65 [2] 99 69 [2] 95 63 [2] 82 68 [2] 99 26 [2] a4 }

  condition:
    any of them
}