rule TTP_XOR_MULT_DOSStub_f10b {
  strings:
    $key_f10b = { a5 63 [2] d1 7b [2] 96 79 [2] d1 68 [2] 9f 64 [2] 93 6e [2] 84 65 [2] 9f 2b [2] a2 }

  condition:
    any of them
}