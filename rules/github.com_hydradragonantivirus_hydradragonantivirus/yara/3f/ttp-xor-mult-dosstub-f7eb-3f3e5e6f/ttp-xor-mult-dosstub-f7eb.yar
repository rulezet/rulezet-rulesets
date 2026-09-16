rule TTP_XOR_MULT_DOSStub_f7eb {
  strings:
    $key_f7eb = { a3 83 [2] d7 9b [2] 90 99 [2] d7 88 [2] 99 84 [2] 95 8e [2] 82 85 [2] 99 cb [2] a4 }

  condition:
    any of them
}