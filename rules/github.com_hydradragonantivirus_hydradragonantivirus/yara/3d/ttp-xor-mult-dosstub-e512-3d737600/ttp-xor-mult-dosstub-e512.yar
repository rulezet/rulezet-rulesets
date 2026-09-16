rule TTP_XOR_MULT_DOSStub_e512 {
  strings:
    $key_e512 = { b1 7a [2] c5 62 [2] 82 60 [2] c5 71 [2] 8b 7d [2] 87 77 [2] 90 7c [2] 8b 32 [2] b6 }

  condition:
    any of them
}