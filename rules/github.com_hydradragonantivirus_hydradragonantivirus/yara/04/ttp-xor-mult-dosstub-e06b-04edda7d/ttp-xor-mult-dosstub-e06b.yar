rule TTP_XOR_MULT_DOSStub_e06b {
  strings:
    $key_e06b = { b4 03 [2] c0 1b [2] 87 19 [2] c0 08 [2] 8e 04 [2] 82 0e [2] 95 05 [2] 8e 4b [2] b3 }

  condition:
    any of them
}