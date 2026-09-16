rule TTP_XOR_MULT_DOSStub_e07b {
  strings:
    $key_e07b = { b4 13 [2] c0 0b [2] 87 09 [2] c0 18 [2] 8e 14 [2] 82 1e [2] 95 15 [2] 8e 5b [2] b3 }

  condition:
    any of them
}