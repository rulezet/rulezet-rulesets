rule TTP_XOR_MULT_DOSStub_f116 {
  strings:
    $key_f116 = { a5 7e [2] d1 66 [2] 96 64 [2] d1 75 [2] 9f 79 [2] 93 73 [2] 84 78 [2] 9f 36 [2] a2 }

  condition:
    any of them
}