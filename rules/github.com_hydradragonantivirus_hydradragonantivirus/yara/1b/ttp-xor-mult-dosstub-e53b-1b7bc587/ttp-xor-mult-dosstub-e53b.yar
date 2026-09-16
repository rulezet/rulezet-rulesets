rule TTP_XOR_MULT_DOSStub_e53b {
  strings:
    $key_e53b = { b1 53 [2] c5 4b [2] 82 49 [2] c5 58 [2] 8b 54 [2] 87 5e [2] 90 55 [2] 8b 1b [2] b6 }

  condition:
    any of them
}