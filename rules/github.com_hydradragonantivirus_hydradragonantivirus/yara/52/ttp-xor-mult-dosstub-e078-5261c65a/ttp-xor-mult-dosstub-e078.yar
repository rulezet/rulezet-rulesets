rule TTP_XOR_MULT_DOSStub_e078 {
  strings:
    $key_e078 = { b4 10 [2] c0 08 [2] 87 0a [2] c0 1b [2] 8e 17 [2] 82 1d [2] 95 16 [2] 8e 58 [2] b3 }

  condition:
    any of them
}