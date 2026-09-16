rule TTP_XOR_MULT_DOSStub_f12b {
  strings:
    $key_f12b = { a5 43 [2] d1 5b [2] 96 59 [2] d1 48 [2] 9f 44 [2] 93 4e [2] 84 45 [2] 9f 0b [2] a2 }

  condition:
    any of them
}