rule TTP_XOR_MULT_DOSStub_e548 {
  strings:
    $key_e548 = { b1 20 [2] c5 38 [2] 82 3a [2] c5 2b [2] 8b 27 [2] 87 2d [2] 90 26 [2] 8b 68 [2] b6 }

  condition:
    any of them
}