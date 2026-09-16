rule TTP_XOR_MULT_DOSStub_f151 {
  strings:
    $key_f151 = { a5 39 [2] d1 21 [2] 96 23 [2] d1 32 [2] 9f 3e [2] 93 34 [2] 84 3f [2] 9f 71 [2] a2 }

  condition:
    any of them
}