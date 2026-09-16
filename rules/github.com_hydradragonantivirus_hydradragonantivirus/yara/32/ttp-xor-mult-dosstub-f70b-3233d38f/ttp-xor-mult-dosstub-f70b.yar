rule TTP_XOR_MULT_DOSStub_f70b {
  strings:
    $key_f70b = { a3 63 [2] d7 7b [2] 90 79 [2] d7 68 [2] 99 64 [2] 95 6e [2] 82 65 [2] 99 2b [2] a4 }

  condition:
    any of them
}