rule TTP_XOR_MULT_DOSStub_f112 {
  strings:
    $key_f112 = { a5 7a [2] d1 62 [2] 96 60 [2] d1 71 [2] 9f 7d [2] 93 77 [2] 84 7c [2] 9f 32 [2] a2 }

  condition:
    any of them
}