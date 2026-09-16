rule TTP_XOR_MULT_DOSStub_c312 {
  strings:
    $key_c312 = { 97 7a [2] e3 62 [2] a4 60 [2] e3 71 [2] ad 7d [2] a1 77 [2] b6 7c [2] ad 32 [2] 90 }

  condition:
    any of them
}